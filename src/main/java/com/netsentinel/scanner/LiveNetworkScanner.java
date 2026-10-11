package com.netsentinel.scanner;

import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import com.netsentinel.model.ScanTarget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Real scanner: TCP connect + banner grab on virtual threads.
 *
 * <p>Two target forms (the {@code cidr} field of the scan request):</p>
 * <ul>
 *   <li>{@code inventory} / {@code lab} / blank: probe the hosts declared in the live inventory file
 *       ({@code netsentinel.scan.live.inventory});</li>
 *   <li>an IPv4 CIDR: sweep it on a default port list. Restricted to loopback, private and link-local
 *       addresses and to at most {@value #MAX_SWEEP_ADDRESSES} addresses. Scan only networks you are
 *       authorised to test.</li>
 * </ul>
 *
 * <p>For each open port the scanner reads a server-first greeting, then tries an HTTP GET, a redis
 * {@code INFO}, and a memcached {@code version} probe until {@link BannerFingerprinter} recognises the
 * product. A virtual EXTERNAL attacker node is added so the graph has an entry point.</p>
 */
@Component
public class LiveNetworkScanner implements NetworkScanner {

    private static final Logger log = LoggerFactory.getLogger(LiveNetworkScanner.class);
    static final int MAX_SWEEP_ADDRESSES = 1024;
    static final List<Integer> DEFAULT_PORTS = List.of(21, 22, 25, 80, 110, 143, 443, 993, 995, 1433, 3306,
            5432, 6379, 8080, 8443, 9200, 11211, 27017);

    @Value("${netsentinel.scan.live.inventory:lab/inventory.yml}")
    private String inventoryPath;

    @Value("${netsentinel.scan.live.connect-timeout-ms:400}")
    private int connectTimeoutMs;

    @Value("${netsentinel.scan.live.read-timeout-ms:700}")
    private int readTimeoutMs;

    @Override
    public String mode() {
        return "live";
    }

    @Override
    public CompletableFuture<List<HostFingerprint>> scan(ScanTarget target, Consumer<HostFingerprint> progress) {
        return CompletableFuture.supplyAsync(() -> {
            List<LiveInventory.Entry> entries = resolveTargets(target.cidr());
            log.info("▶ Live scan of {} ({} hosts)", target.cidr(), entries.size());

            // several inventory entries may share an address (lab on loopback): make ids unique
            Map<String, Long> perAddress = new HashMap<>();
            entries.forEach(e -> perAddress.merge(e.address(), 1L, Long::sum));

            List<HostFingerprint> results = new ArrayList<>();
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<Optional<HostFingerprint>>> futures = new ArrayList<>();
                for (LiveInventory.Entry e : entries) {
                    futures.add(executor.submit(() -> probeHost(e, perAddress.get(e.address()) > 1, progress)));
                }
                for (var f : futures) {
                    try {
                        f.get().ifPresent(results::add);
                    } catch (Exception ex) {
                        log.warn("Host probe failed: {}", ex.getMessage());
                    }
                }
            }
            results.add(externalAttacker());
            log.info("✓ Live scan complete: {} hosts with open ports", results.size() - 1);
            return results;
        });
    }

    // ------------------------------------------------------------------ targets

    List<LiveInventory.Entry> resolveTargets(String cidr) {
        String t = cidr == null ? "" : cidr.trim();
        if (t.isEmpty() || t.equalsIgnoreCase("inventory") || t.equalsIgnoreCase("lab")) {
            try {
                return LiveInventory.load(Path.of(inventoryPath));
            } catch (IOException e) {
                throw new IllegalStateException("cannot read live inventory " + inventoryPath + ": " + e.getMessage(), e);
            }
        }
        List<String> addresses = expandCidr(t);
        List<LiveInventory.Entry> out = new ArrayList<>();
        for (String a : addresses) {
            out.add(new LiveInventory.Entry(a, a, DEFAULT_PORTS, NetworkTier.APPLICATION, 5, "unknown"));
        }
        return out;
    }

    /** Expands an IPv4 CIDR; rejects public ranges and anything larger than {@link #MAX_SWEEP_ADDRESSES}. */
    static List<String> expandCidr(String cidr) {
        String[] parts = cidr.split("/");
        try {
            InetAddress base = InetAddress.getByName(parts[0]);
            int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;
            if (!(base instanceof Inet4Address) || prefix < 0 || prefix > 32) {
                throw new IllegalArgumentException("not an IPv4 CIDR: " + cidr);
            }
            if (!(base.isLoopbackAddress() || base.isSiteLocalAddress() || base.isLinkLocalAddress())) {
                throw new IllegalArgumentException("refusing to scan a public address range: " + cidr);
            }
            long size = 1L << (32 - prefix);
            if (size > MAX_SWEEP_ADDRESSES) {
                throw new IllegalArgumentException("range too large (max " + MAX_SWEEP_ADDRESSES + " addresses): " + cidr);
            }
            byte[] b = base.getAddress();
            long start = ((b[0] & 0xFFL) << 24 | (b[1] & 0xFFL) << 16 | (b[2] & 0xFFL) << 8 | (b[3] & 0xFFL))
                    & (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            List<String> out = new ArrayList<>();
            for (long i = 0; i < size; i++) {
                long v = start + i;
                if (size > 2 && (i == 0 || i == size - 1)) continue; // network / broadcast
                out.add(((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255));
            }
            return out;
        } catch (UnknownHostException | NumberFormatException e) {
            throw new IllegalArgumentException("invalid target: " + cidr, e);
        }
    }

    // ------------------------------------------------------------------ probing

    private Optional<HostFingerprint> probeHost(LiveInventory.Entry e, boolean sharedAddress, Consumer<HostFingerprint> progress) {
        Map<Integer, String> banners = new TreeMap<>();
        List<Integer> open = new ArrayList<>();
        Set<String> cpes = new LinkedHashSet<>();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Map<Integer, Future<PortResult>> futures = new LinkedHashMap<>();
            for (int port : e.ports()) futures.put(port, executor.submit(() -> probePort(e.address(), port)));
            for (var en : futures.entrySet()) {
                try {
                    PortResult r = en.getValue().get();
                    if (r.open()) {
                        open.add(en.getKey());
                        banners.put(en.getKey(), r.summary());
                        r.detected().ifPresent(d -> cpes.add(d.cpe()));
                    }
                } catch (Exception ex) {
                    log.debug("port probe failed {}:{}: {}", e.address(), en.getKey(), ex.getMessage());
                }
            }
        }
        if (open.isEmpty()) return Optional.empty();

        String id = sharedAddress ? e.address() + ":" + e.ports().get(0) : e.address();
        HostFingerprint fp = new HostFingerprint(id, e.name(), open, banners, List.copyOf(cpes),
                e.os(), e.tier(), e.criticality());
        log.debug("  ✓ {} ({}) open={} cpes={}", e.name(), id, open, cpes);
        if (progress != null) progress.accept(fp);
        return Optional.of(fp);
    }

    record PortResult(boolean open, String summary, Optional<BannerFingerprinter.Detected> detected) {
        static PortResult closed() { return new PortResult(false, "", Optional.empty()); }
    }

    PortResult probePort(String address, int port) {
        if (!connects(address, port)) return PortResult.closed();

        String first = "";
        // 1. server-first greeting (SSH, FTP, SMTP, MySQL, ...)
        String greeting = exchange(address, port, null);
        if (!greeting.isEmpty()) {
            first = greeting;
            var d = BannerFingerprinter.identify(greeting);
            if (d.isPresent()) return new PortResult(true, summarize(greeting), d);
        }
        // 2. client-first probes: HTTP, redis, memcached
        String[] probes = {
                "GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: NetSentinel\r\n\r\n",
                "INFO server\r\n",
                "version\r\n"
        };
        for (String probe : probes) {
            String resp = exchange(address, port, probe);
            if (first.isEmpty() && !resp.isEmpty()) first = resp;
            var d = BannerFingerprinter.identify(resp);
            if (d.isPresent()) return new PortResult(true, summarize(resp), d);
        }
        return new PortResult(true, summarize(first), Optional.empty());
    }

    private boolean connects(String address, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(address, port), connectTimeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Opens a fresh connection, optionally sends a probe, and reads whatever arrives within the timeout. */
    private String exchange(String address, int port, String probe) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(address, port), connectTimeoutMs);
            s.setSoTimeout(readTimeoutMs);
            if (probe != null) {
                OutputStream out = s.getOutputStream();
                out.write(probe.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
            }
            InputStream in = s.getInputStream();
            byte[] buf = new byte[4096];
            int total = 0;
            long deadline = System.nanoTime() + readTimeoutMs * 1_000_000L;
            while (total < buf.length && System.nanoTime() < deadline) {
                try {
                    int n = in.read(buf, total, buf.length - total);
                    if (n < 0) break;
                    total += n;
                    if (probe == null) break; // greeting: one read is enough
                } catch (SocketTimeoutException t) {
                    break;
                }
            }
            return new String(buf, 0, total, StandardCharsets.ISO_8859_1);
        } catch (IOException e) {
            return "";
        }
    }

    private static String summarize(String raw) {
        String s = raw.replaceAll("[^\\x20-\\x7E\\r\\n]", ".").trim();
        int nl = s.indexOf('\n');
        String firstLine = nl > 0 ? s.substring(0, nl).trim() : s;
        // for HTTP, prefer the Server header as the summary
        for (String line : s.split("\\r?\\n")) {
            if (line.toLowerCase().startsWith("server:") || line.toLowerCase().startsWith("x-jenkins:")) {
                return line.trim();
            }
        }
        return firstLine.length() > 120 ? firstLine.substring(0, 120) : firstLine;
    }

    private static HostFingerprint externalAttacker() {
        return new HostFingerprint("internet", "internet-attacker", List.of(), Map.of(), List.of(),
                "External", NetworkTier.EXTERNAL, 0);
    }
}

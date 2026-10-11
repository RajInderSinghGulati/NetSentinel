package com.netsentinel.scanner;

import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import com.netsentinel.model.ScanTarget;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

/** Runs the real scanner over real TCP sockets against small in-process fake services. */
class LiveNetworkScannerTest {

    private final List<ServerSocket> servers = new ArrayList<>();
    private final InetAddress loopback = InetAddress.getLoopbackAddress();

    @BeforeEach
    void init() {}

    @AfterEach
    void shutdown() throws IOException {
        for (ServerSocket s : servers) s.close();
    }

    /** Starts a service; the handler gets each accepted socket on its own thread. */
    private int serve(Function<Socket, Void> handler) throws IOException {
        ServerSocket ss = new ServerSocket(0, 50, loopback);
        servers.add(ss);
        Thread.ofVirtual().start(() -> {
            while (!ss.isClosed()) {
                try {
                    Socket c = ss.accept();
                    Thread.ofVirtual().start(() -> { handler.apply(c); return; });
                } catch (IOException e) {
                    return;
                }
            }
        });
        return ss.getLocalPort();
    }

    private static String readUntilBlankLine(Socket c) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.ISO_8859_1));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null && !line.isEmpty()) sb.append(line).append("\r\n");
        return sb.toString();
    }

    private int httpApache() throws IOException {
        return serve(c -> {
            try (c) {
                readUntilBlankLine(c);
                c.getOutputStream().write(("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 2\r\n\r\nok")
                        .getBytes(StandardCharsets.ISO_8859_1));
            } catch (IOException ignored) {}
            return null;
        });
    }

    /** Behaves like redis: errors on unknown commands, answers INFO. */
    private int redis() throws IOException {
        return serve(c -> {
            try (c) {
                BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.ISO_8859_1));
                OutputStream o = c.getOutputStream();
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.startsWith("INFO")) {
                        o.write("$60\r\n# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\n\r\n".getBytes());
                    } else if (!line.isEmpty()) {
                        o.write(("-ERR unknown command '" + line.split(" ")[0] + "'\r\n").getBytes());
                    }
                    o.flush();
                }
            } catch (IOException ignored) {}
            return null;
        });
    }

    private int memcached() throws IOException {
        return serve(c -> {
            try (c) {
                BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.ISO_8859_1));
                OutputStream o = c.getOutputStream();
                String line;
                while ((line = r.readLine()) != null) {
                    o.write((line.startsWith("version") ? "VERSION 1.6.9\r\n" : "ERROR\r\n").getBytes());
                    o.flush();
                }
            } catch (IOException ignored) {}
            return null;
        });
    }

    private int sshGreeting() throws IOException {
        return serve(c -> {
            try (c) {
                c.getOutputStream().write("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n".getBytes());
                c.getOutputStream().flush();
                c.getInputStream().read();
            } catch (IOException ignored) {}
            return null;
        });
    }

    /** Accepts and stays silent: open port, no banner. */
    private int silent() throws IOException {
        return serve(c -> {
            try (c) {
                c.getInputStream().read();
            } catch (IOException ignored) {}
            return null;
        });
    }

    private int closedPort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, loopback)) {
            return s.getLocalPort();
        }
    }

    private LiveNetworkScanner scannerFor(Path dir, String yaml) throws IOException {
        Path inv = dir.resolve("inventory.yml");
        Files.writeString(inv, yaml);
        LiveNetworkScanner s = new LiveNetworkScanner();
        ReflectionTestUtils.setField(s, "inventoryPath", inv.toString());
        ReflectionTestUtils.setField(s, "connectTimeoutMs", 400);
        ReflectionTestUtils.setField(s, "readTimeoutMs", 500);
        return s;
    }

    @Test
    void identifiesServicesOverRealSockets(@TempDir Path dir) throws Exception {
        int web = httpApache(), cache = redis(), mem = memcached(), ssh = sshGreeting(), quiet = silent(), closed = closedPort();
        String yaml = """
                hosts:
                  - {name: web-dmz,   address: 127.0.0.1, ports: [%d, %d], tier: DMZ, criticality: 5, os: Alpine}
                  - {name: app-cache, address: 127.0.0.1, ports: [%d, %d], tier: APPLICATION, criticality: 6}
                  - {name: data-mem,  address: 127.0.0.1, ports: [%d],     tier: DATA, criticality: 7}
                  - {name: ghost,     address: 127.0.0.1, ports: [%d],     tier: DATA, criticality: 3}
                """.formatted(web, quiet, cache, ssh, mem, closed);
        LiveNetworkScanner scanner = scannerFor(dir, yaml);

        List<HostFingerprint> seen = new CopyOnWriteArrayList<>();
        List<HostFingerprint> hosts = scanner.scan(new ScanTarget("lab", "live"), seen::add).get();

        // 3 live hosts + virtual attacker; the host whose only port is closed is not reported
        assertEquals(4, hosts.size());
        assertEquals(3, seen.size());
        assertTrue(hosts.stream().noneMatch(h -> h.hostname().equals("ghost")));

        HostFingerprint webHost = byName(hosts, "web-dmz");
        assertEquals(NetworkTier.DMZ, webHost.tier());
        assertEquals(List.of("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"), webHost.cpeStrings());
        assertEquals(2, webHost.openPorts().size(), "silent port is open but has no banner");

        HostFingerprint cacheHost = byName(hosts, "app-cache");
        assertTrue(cacheHost.cpeStrings().contains("cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*"));
        assertTrue(cacheHost.cpeStrings().contains("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"));

        assertEquals(List.of("cpe:2.3:a:memcached:memcached:1.6.9:*:*:*:*:*:*:*"), byName(hosts, "data-mem").cpeStrings());

        // hosts sharing an address get unique ids
        assertEquals(3, hosts.stream().filter(h -> h.tier() != NetworkTier.EXTERNAL).map(HostFingerprint::ip).distinct().count());

        HostFingerprint attacker = hosts.stream().filter(h -> h.tier() == NetworkTier.EXTERNAL).findFirst().orElseThrow();
        assertTrue(attacker.cpeStrings().isEmpty());
    }

    private static HostFingerprint byName(List<HostFingerprint> hosts, String name) {
        return hosts.stream().filter(h -> h.hostname().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void cidrSweepFindsOnlyOpenPorts() throws Exception {
        // sweeping 127.0.0.1/32 on the default port list finds nothing unless something listens there
        LiveNetworkScanner scanner = scannerFor(Path.of(System.getProperty("java.io.tmpdir")), "hosts: []");
        List<HostFingerprint> hosts = scanner.scan(new ScanTarget("127.0.0.1/32", "live"), null).get();
        assertTrue(hosts.stream().allMatch(h -> h.tier() == NetworkTier.EXTERNAL || !h.openPorts().isEmpty()));
    }

    @Test
    void cidrGuards() {
        assertEquals(List.of("127.0.0.1"), LiveNetworkScanner.expandCidr("127.0.0.1/32"));
        assertEquals(List.of("10.0.0.1", "10.0.0.2"), LiveNetworkScanner.expandCidr("10.0.0.0/30"));
        assertThrows(IllegalArgumentException.class, () -> LiveNetworkScanner.expandCidr("8.8.8.8/32"), "public range");
        assertThrows(IllegalArgumentException.class, () -> LiveNetworkScanner.expandCidr("10.0.0.0/8"), "too large");
        assertThrows(IllegalArgumentException.class, () -> LiveNetworkScanner.expandCidr("not-an-ip"));
    }

    @Test
    void inventoryValidation() {
        assertThrows(IllegalArgumentException.class, () -> LiveInventory.parse(java.util.Map.of("nothing", 1)));
        assertThrows(IllegalArgumentException.class, () -> LiveInventory.parse(
                java.util.Map.of("hosts", List.of(java.util.Map.of("name", "x", "address", "127.0.0.1")))));
    }
}

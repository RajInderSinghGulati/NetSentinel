package com.netsentinel.scanner;

import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import com.netsentinel.model.ScanTarget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Simulated network scanner that generates a realistic multi-tier enterprise
 * network topology for demonstration purposes.
 *
 * <p>Uses Java 21 Virtual Threads via {@code Executors.newVirtualThreadPerTaskExecutor()}
 * to demonstrate high-concurrency scanning patterns. Each "probe" runs on its own
 * virtual thread with simulated latency.</p>
 *
 * <p>The simulated network contains:
 * <ul>
 *   <li><b>DMZ Tier:</b> Web servers (Apache, Nginx), mail gateway, VPN endpoint</li>
 *   <li><b>App Tier:</b> Tomcat, Node.js, Spring Boot API servers</li>
 *   <li><b>Data Tier:</b> PostgreSQL, MongoDB, Redis, Elasticsearch</li>
 *   <li><b>Crown Jewels:</b> HR database, financial system, secrets vault</li>
 * </ul></p>
 */
@Component
public class SimulatedNetworkScanner implements NetworkScanner {

    private static final Logger log = LoggerFactory.getLogger(SimulatedNetworkScanner.class);
    private static final int SIMULATED_DELAY_MS = 150;

    @Override
    public String mode() {
        return "simulated";
    }

    @Override
    public CompletableFuture<List<HostFingerprint>> scan(ScanTarget target, Consumer<HostFingerprint> progressCallback) {
        return CompletableFuture.supplyAsync(() -> {
            log.info("▶ Starting simulated scan of {} with virtual threads", target.cidr());
            List<HostFingerprint> hosts = buildSimulatedNetwork(target.cidr());
            List<HostFingerprint> results = Collections.synchronizedList(new ArrayList<>());

            // Use Virtual Threads for concurrent probing
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<?>> futures = new ArrayList<>();

                for (HostFingerprint host : hosts) {
                    futures.add(executor.submit(() -> {
                        simulateProbe(host);
                        results.add(host);
                        if (progressCallback != null) {
                            progressCallback.accept(host);
                        }
                        log.debug("  ✓ Discovered {} ({}) — {} open ports, {} CPEs",
                                host.hostname(), host.ip(),
                                host.openPorts().size(), host.cpeStrings().size());
                    }));
                }

                // Wait for all virtual threads to complete
                for (Future<?> f : futures) {
                    try { f.get(10, TimeUnit.SECONDS); }
                    catch (Exception e) { log.warn("Scan thread failed: {}", e.getMessage()); }
                }
            }

            log.info("✓ Scan complete: {} hosts discovered in subnet {}", results.size(), target.cidr());
            return results;
        });
    }

    /**
     * Simulates network probe latency (banner grabbing, TLS cert parsing, etc.)
     */
    private void simulateProbe(HostFingerprint host) {
        try {
            // Simulate variable latency based on number of open ports
            int delay = SIMULATED_DELAY_MS + (host.openPorts().size() * 20);
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Builds a realistic multi-tier enterprise network topology.
     */
    private List<HostFingerprint> buildSimulatedNetwork(String cidr) {
        String baseIp = cidr.split("/")[0];
        String subnet = baseIp.substring(0, baseIp.lastIndexOf('.') + 1);

        List<HostFingerprint> hosts = new ArrayList<>();

        // ═══════════════════════════════════════
        // External Attacker Node (virtual)
        // ═══════════════════════════════════════
        hosts.add(new HostFingerprint(
                "0.0.0.0", "attacker-entry", List.of(),
                Map.of(), List.of(), "External", NetworkTier.EXTERNAL, 0
        ));

        // ═══════════════════════════════════════
        // DMZ TIER — Internet-facing services
        // ═══════════════════════════════════════
        hosts.add(new HostFingerprint(
                subnet + "10", "web-server-01",
                List.of(80, 443, 22),
                Map.of(80, "Apache/2.4.49 (Ubuntu)", 443, "Apache/2.4.49 OpenSSL/1.1.1", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                         "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"),
                "Ubuntu 20.04 LTS", NetworkTier.DMZ, 4
        ));

        hosts.add(new HostFingerprint(
                subnet + "11", "web-server-02",
                List.of(80, 443, 22),
                Map.of(80, "nginx/1.18.0", 443, "nginx/1.18.0", 22, "OpenSSH_8.4p1"),
                List.of("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"),
                "Debian 11", NetworkTier.DMZ, 3
        ));

        hosts.add(new HostFingerprint(
                subnet + "12", "mail-gateway",
                List.of(25, 587, 993, 22),
                Map.of(25, "Postfix smtpd", 587, "Postfix smtpd", 993, "Dovecot imapd"),
                List.of("cpe:2.3:a:postfix:postfix:3.5.6:*:*:*:*:*:*:*"),
                "CentOS 8", NetworkTier.DMZ, 5
        ));

        hosts.add(new HostFingerprint(
                subnet + "13", "vpn-gateway",
                List.of(443, 1194),
                Map.of(443, "OpenVPN AS 2.9.0", 1194, "OpenVPN 2.5.1"),
                List.of("cpe:2.3:a:openvpn:openvpn:2.5.1:*:*:*:*:*:*:*"),
                "Ubuntu 20.04 LTS", NetworkTier.DMZ, 6
        ));

        // ═══════════════════════════════════════
        // APPLICATION TIER — Internal app servers
        // ═══════════════════════════════════════
        hosts.add(new HostFingerprint(
                subnet + "20", "app-server-tomcat",
                List.of(8080, 8443, 22),
                Map.of(8080, "Apache Tomcat/9.0.50", 8443, "Apache Tomcat/9.0.50", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"),
                "Ubuntu 22.04 LTS", NetworkTier.APPLICATION, 6
        ));

        hosts.add(new HostFingerprint(
                subnet + "21", "app-server-spring",
                List.of(8080, 8443, 22, 5005),
                Map.of(8080, "Spring Boot 2.7.5", 22, "OpenSSH_8.9p1"),
                List.of("cpe:2.3:a:vmware:spring_boot:2.7.5:*:*:*:*:*:*:*",
                         "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
                "Ubuntu 22.04 LTS", NetworkTier.APPLICATION, 7
        ));

        hosts.add(new HostFingerprint(
                subnet + "22", "api-gateway",
                List.of(8080, 8443, 9090),
                Map.of(8080, "Kong/2.8.1", 9090, "Prometheus/2.37"),
                List.of("cpe:2.3:a:kong:kong:2.8.1:*:*:*:*:*:*:*"),
                "Alpine Linux 3.16", NetworkTier.APPLICATION, 5
        ));

        hosts.add(new HostFingerprint(
                subnet + "23", "ci-cd-server",
                List.of(8080, 50000, 22),
                Map.of(8080, "Jenkins/2.346.1", 50000, "Jenkins Agent", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:jenkins:jenkins:2.346.1:*:*:*:*:*:*:*"),
                "Ubuntu 20.04 LTS", NetworkTier.APPLICATION, 7
        ));

        // ═══════════════════════════════════════
        // DATA TIER — Databases and caches
        // ═══════════════════════════════════════
        hosts.add(new HostFingerprint(
                subnet + "30", "db-postgres-primary",
                List.of(5432, 22),
                Map.of(5432, "PostgreSQL 13.3", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:postgresql:postgresql:13.3:*:*:*:*:*:*:*"),
                "Ubuntu 20.04 LTS", NetworkTier.DATA, 8
        ));

        hosts.add(new HostFingerprint(
                subnet + "31", "db-mongodb",
                List.of(27017, 22),
                Map.of(27017, "MongoDB 5.0.3", 22, "OpenSSH_8.4p1"),
                List.of("cpe:2.3:a:mongodb:mongodb:5.0.3:*:*:*:*:*:*:*"),
                "Debian 11", NetworkTier.DATA, 7
        ));

        hosts.add(new HostFingerprint(
                subnet + "32", "cache-redis",
                List.of(6379, 22),
                Map.of(6379, "Redis/6.2.6", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*"),
                "Ubuntu 20.04 LTS", NetworkTier.DATA, 5
        ));

        hosts.add(new HostFingerprint(
                subnet + "33", "search-elastic",
                List.of(9200, 9300, 22),
                Map.of(9200, "Elasticsearch/7.17.0", 9300, "Elasticsearch transport"),
                List.of("cpe:2.3:a:elastic:elasticsearch:7.17.0:*:*:*:*:*:*:*"),
                "CentOS 8", NetworkTier.DATA, 6
        ));

        // ═══════════════════════════════════════
        // CROWN JEWELS — High-value targets
        // ═══════════════════════════════════════
        hosts.add(new HostFingerprint(
                subnet + "40", "hr-database",
                List.of(1433, 22),
                Map.of(1433, "Microsoft SQL Server 2019", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*"),
                "Windows Server 2019", NetworkTier.CROWN_JEWEL, 10
        ));

        hosts.add(new HostFingerprint(
                subnet + "41", "financial-system",
                List.of(8443, 22),
                Map.of(8443, "SAP NetWeaver 7.50", 22, "OpenSSH_8.2p1"),
                List.of("cpe:2.3:a:sap:netweaver:7.50:*:*:*:*:*:*:*"),
                "SUSE Linux Enterprise 15", NetworkTier.CROWN_JEWEL, 10
        ));

        hosts.add(new HostFingerprint(
                subnet + "42", "secrets-vault",
                List.of(8200, 22),
                Map.of(8200, "Vault v1.11.3", 22, "OpenSSH_8.9p1"),
                List.of("cpe:2.3:a:hashicorp:vault:1.11.3:*:*:*:*:*:*:*"),
                "Ubuntu 22.04 LTS", NetworkTier.CROWN_JEWEL, 9
        ));

        return hosts;
    }
}

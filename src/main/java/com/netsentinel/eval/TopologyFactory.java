package com.netsentinel.eval;

import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.HostFingerprint.NetworkTier;

import java.util.*;

/**
 * Evaluation topologies. Hosts carry real product CPEs, so the CVEs (and therefore the attack graph)
 * come from the same NVD snapshot the application uses. Hand-built topologies are fixed; synthetic ones
 * are generated from a seed.
 */
public final class TopologyFactory {

    private TopologyFactory() {}

    private static String cpe(String vendor, String product, String version) {
        return "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*".formatted(vendor, product, version);
    }

    static final String APACHE = cpe("apache", "http_server", "2.4.49");
    static final String NGINX = cpe("f5", "nginx", "1.18.0");
    static final String OPENVPN = cpe("openvpn", "openvpn", "2.5.1");
    static final String POSTFIX = cpe("postfix", "postfix", "3.5.6");
    static final String OPENSSL = cpe("openssl", "openssl", "1.1.1");
    static final String TOMCAT = cpe("apache", "tomcat", "9.0.50");
    static final String SPRING = cpe("vmware", "spring_boot", "2.7.5");
    static final String LOG4J = cpe("apache", "log4j", "2.14.1");
    static final String JENKINS = cpe("jenkins", "jenkins", "2.346.1");
    static final String KONG = cpe("kong", "kong", "2.8.1");
    static final String POSTGRES = cpe("postgresql", "postgresql", "13.3");
    static final String MONGO = cpe("mongodb", "mongodb", "5.0.3");
    static final String REDIS = cpe("redis", "redis", "6.2.6");
    static final String ELASTIC = cpe("elastic", "elasticsearch", "7.17.0");
    static final String MEMCACHED = cpe("memcached", "memcached", "1.6.9");
    static final String SQLSERVER = cpe("microsoft", "sql_server", "2019");
    static final String NETWEAVER = cpe("sap", "netweaver", "7.50");
    static final String VAULT = cpe("hashicorp", "vault", "1.11.3");

    private static final Map<NetworkTier, List<String>> POOLS = Map.of(
            NetworkTier.DMZ, List.of(APACHE, NGINX, OPENVPN, POSTFIX, OPENSSL),
            NetworkTier.APPLICATION, List.of(TOMCAT, SPRING, LOG4J, JENKINS, KONG, OPENSSL),
            NetworkTier.DATA, List.of(POSTGRES, MONGO, REDIS, ELASTIC, MEMCACHED),
            NetworkTier.CROWN_JEWEL, List.of(SQLSERVER, NETWEAVER, VAULT, REDIS, POSTGRES));

    private static HostFingerprint host(String id, String name, NetworkTier tier, int criticality, String... cpes) {
        return new HostFingerprint(id, name, List.of(80), Map.of(), List.of(cpes), "Linux", tier, criticality);
    }

    private static HostFingerprint attacker() {
        return new HostFingerprint("internet", "internet-attacker", List.of(), Map.of(), List.of(),
                "External", NetworkTier.EXTERNAL, 0);
    }

    /** The five-container Docker lab, as the live scanner reports it (so evaluation needs no Docker). */
    public static List<HostFingerprint> lab() {
        return List.of(attacker(),
                host("127.0.0.1:18080", "web-dmz", NetworkTier.DMZ, 5, APACHE),
                host("127.0.0.1:18081", "proxy-dmz", NetworkTier.DMZ, 4, NGINX),
                host("127.0.0.1:18379", "app-cache", NetworkTier.APPLICATION, 6, REDIS),
                host("127.0.0.1:18211", "data-memcached", NetworkTier.DATA, 7, MEMCACHED),
                host("127.0.0.1:18380", "secrets-vault", NetworkTier.CROWN_JEWEL, 10, REDIS));
    }

    /** A three-tier web shop: load balancer, web and app servers, cache and databases, payment and secrets. */
    public static List<HostFingerprint> ecommerce() {
        return List.of(attacker(),
                host("10.1.0.2", "lb-nginx", NetworkTier.DMZ, 4, NGINX),
                host("10.1.0.3", "web-1", NetworkTier.DMZ, 4, APACHE),
                host("10.1.0.4", "web-2", NetworkTier.DMZ, 4, APACHE, OPENSSL),
                host("10.1.1.2", "app-tomcat", NetworkTier.APPLICATION, 6, TOMCAT),
                host("10.1.1.3", "app-spring", NetworkTier.APPLICATION, 7, SPRING, LOG4J),
                host("10.1.1.4", "build-jenkins", NetworkTier.APPLICATION, 5, JENKINS),
                host("10.1.2.2", "db-postgres", NetworkTier.DATA, 8, POSTGRES),
                host("10.1.2.3", "cache-redis", NetworkTier.DATA, 6, REDIS),
                host("10.1.2.4", "search-es", NetworkTier.DATA, 6, ELASTIC),
                host("10.1.3.2", "payments-sql", NetworkTier.CROWN_JEWEL, 10, SQLSERVER),
                host("10.1.3.3", "secrets-vault", NetworkTier.CROWN_JEWEL, 10, VAULT));
    }

    /**
     * Random network of {@code n} hosts (plus the attacker): 10% DMZ, 30% application, 50% data, 10%
     * crown jewels, each running one or two products drawn from its tier's pool.
     */
    public static List<HostFingerprint> synthetic(int n, long seed) {
        Random rnd = new Random(seed);
        int dmz = Math.max(1, Math.round(n * 0.10f));
        int app = Math.max(1, Math.round(n * 0.30f));
        int cj = Math.max(1, Math.round(n * 0.10f));
        int data = Math.max(1, n - dmz - app - cj);

        List<HostFingerprint> hosts = new ArrayList<>();
        hosts.add(attacker());
        int counter = 0;
        for (var spec : List.of(
                new Object[]{NetworkTier.DMZ, dmz, 3, 6},
                new Object[]{NetworkTier.APPLICATION, app, 4, 7},
                new Object[]{NetworkTier.DATA, data, 5, 8},
                new Object[]{NetworkTier.CROWN_JEWEL, cj, 9, 10})) {
            NetworkTier tier = (NetworkTier) spec[0];
            int count = (Integer) spec[1], lo = (Integer) spec[2], hi = (Integer) spec[3];
            List<String> pool = POOLS.get(tier);
            for (int i = 0; i < count; i++, counter++) {
                Set<String> cpes = new LinkedHashSet<>();
                cpes.add(pool.get(rnd.nextInt(pool.size())));
                if (rnd.nextBoolean()) cpes.add(pool.get(rnd.nextInt(pool.size())));
                String id = "10.%d.%d.%d".formatted(counter / 65025, (counter / 255) % 255, counter % 255 + 1);
                hosts.add(host(id, tier.name().toLowerCase().replace("_", "") + "-" + i, tier,
                        lo + rnd.nextInt(hi - lo + 1), cpes.toArray(new String[0])));
            }
        }
        return hosts;
    }
}

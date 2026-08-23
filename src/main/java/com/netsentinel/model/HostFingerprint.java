package com.netsentinel.model;

import java.util.List;
import java.util.Map;

/**
 * Strongly-typed fingerprint of a discovered network host.
 *
 * <p>Produced by Tier 1 (Ingestion & Discovery Engine) after probing a target.
 * Contains all information extracted from TCP SYN/ACK handshakes, TLS certificate
 * parsing, and service banner grabbing.</p>
 *
 * @param ip          IPv4 address of the host (e.g., "192.168.10.5")
 * @param hostname    Resolved hostname or reverse DNS name
 * @param openPorts   List of open TCP ports discovered
 * @param banners     Map of port → service banner string (e.g., 80 → "Apache/2.4.49")
 * @param cpeStrings  CPE 2.3 identifiers extracted from banner analysis
 * @param osTag       Operating system identification (e.g., "Ubuntu 20.04 LTS")
 * @param tier        Network tier classification (DMZ, APP, DATA, CROWN_JEWEL)
 * @param criticality Asset criticality rating (1-10, where 10 = mission critical)
 */
public record HostFingerprint(
        String ip,
        String hostname,
        List<Integer> openPorts,
        Map<Integer, String> banners,
        List<String> cpeStrings,
        String osTag,
        NetworkTier tier,
        int criticality
) {

    /**
     * Network tier classification for segmenting hosts
     * into logical security zones.
     */
    public enum NetworkTier {
        /** Internet-facing DMZ zone (web servers, mail gateways) */
        DMZ,
        /** Internal application tier (app servers, middleware) */
        APPLICATION,
        /** Data storage tier (databases, caches) */
        DATA,
        /** High-value internal targets (financial systems, HR databases) */
        CROWN_JEWEL,
        /** External attacker entry point (virtual node) */
        EXTERNAL
    }

    /**
     * Returns a compact display label for this host.
     */
    public String displayLabel() {
        return hostname != null && !hostname.isBlank() ? hostname : ip;
    }
}

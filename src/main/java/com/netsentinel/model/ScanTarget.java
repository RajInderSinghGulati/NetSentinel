package com.netsentinel.model;

/**
 * Input record representing a network scan target.
 *
 * @param cidr        CIDR notation subnet (e.g., "192.168.10.0/24")
 * @param label       Human-readable label for the scan job
 * @param scanDepth   How deep to probe (QUICK, STANDARD, DEEP)
 * @param mode        Scanner to use: "simulated" or "live" (null = configured default)
 */
public record ScanTarget(
        String cidr,
        String label,
        ScanDepth scanDepth,
        String mode
) {

    public enum ScanDepth {
        QUICK,      // Top 100 ports only
        STANDARD,   // Top 1000 ports
        DEEP        // Full 65535 port scan
    }

    /**
     * Convenience constructor with defaults.
     */
    public ScanTarget(String cidr) {
        this(cidr, "Scan of " + cidr, ScanDepth.STANDARD, null);
    }

    public ScanTarget(String cidr, String mode) {
        this(cidr, "Scan of " + cidr, ScanDepth.STANDARD, mode);
    }
}

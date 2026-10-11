package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;

import java.util.*;

/**
 * Chooses the version to upgrade a product to, from NVD fixed-in ranges.
 *
 * <p>Starting at the installed version, repeatedly find the CVEs that still affect the candidate version,
 * move to the smallest version that escapes all of them, and stop when nothing affects it or what remains
 * has no known fix (for example "all versions" entries, or ranges without an upper bound). CVEs that
 * cannot be fixed this way are reported as residual: upgrading does not remove them.</p>
 */
public final class UpgradePlanner {

    /**
     * @param targetVersion version to upgrade to (a {@link CpeMatcher#successor} value means "any newer
     *                      release than the prefix"); null if the upgrade fixes nothing
     * @param targetCpe     the product's CPE at the target version, null if no target
     * @param fixedCveIds   CVEs (among the input) not affecting the target version
     * @param residualCveIds CVEs still affecting every candidate version
     */
    public record Upgrade(String targetVersion, String targetCpe, Set<String> fixedCveIds, Set<String> residualCveIds) {
        public boolean hasTarget() {
            return targetVersion != null;
        }

        /** Human-readable target, e.g. "8.6.3" or "newer than 2.4.50". */
        public String targetLabel() {
            if (targetVersion == null) return "no fix known";
            return CpeMatcher.isSuccessor(targetVersion)
                    ? "newer than " + targetVersion.substring(0, targetVersion.length() - 4) : targetVersion;
        }
    }

    private UpgradePlanner() {}

    public static String withVersion(String cpe, String version) {
        String[] p = cpe.split(":", -1);
        p[5] = version;
        return String.join(":", p);
    }

    private static List<String> productEntries(CveRecord c, String cpe) {
        String[] q = cpe.split(":");
        List<String> out = new ArrayList<>();
        for (String e : c.affectedCpes()) {
            String[] a = e.split("#")[0].split(":");
            if (a.length > 5 && a[3].equalsIgnoreCase(q[3]) && a[4].equalsIgnoreCase(q[4])) out.add(e);
        }
        return out;
    }

    /** Fixed-in version at {@code version}; empty if the CVE does not affect it; "" if affected but unfixable. */
    private static Optional<String> fixedIn(CveRecord c, String cpe, String original, String version) {
        List<String> entries = productEntries(c, cpe);
        if (entries.isEmpty()) {
            // no range data for this product (hand-written records): assume any upgrade fixes it
            return version.equals(original) ? Optional.of(CpeMatcher.successor(version)) : Optional.empty();
        }
        String at = withVersion(cpe, version);
        String best = null;
        boolean affected = false;
        for (String e : entries) {
            CpeMatcher.Fix f = CpeMatcher.fixFor(at, e);
            if (!f.affected()) continue;
            affected = true;
            if (f.fixedIn() == null) return Optional.of("");
            if (best == null || CpeMatcher.compareVersions(f.fixedIn(), best) > 0) best = f.fixedIn();
        }
        return affected ? Optional.of(best) : Optional.empty();
    }

    public static Upgrade plan(String cpe, Collection<CveRecord> cves) {
        String original = cpe.split(":")[5];
        Map<String, CveRecord> remaining = new LinkedHashMap<>();
        for (CveRecord c : cves) remaining.putIfAbsent(c.cveId(), c);
        Set<String> residual = new LinkedHashSet<>();
        String target = original;

        for (int iter = 0; iter < 50; iter++) {
            String next = target;
            boolean affecting = false;
            for (CveRecord c : new ArrayList<>(remaining.values())) {
                Optional<String> f = fixedIn(c, cpe, original, target);
                if (f.isEmpty()) continue;
                affecting = true;
                if (f.get().isEmpty()) {
                    residual.add(c.cveId());
                    remaining.remove(c.cveId());
                } else if (CpeMatcher.compareVersions(f.get(), next) > 0) {
                    next = f.get();
                }
            }
            if (!affecting || next.equals(target)) break;
            target = next;
        }

        if (target.equals(original)) {
            return new Upgrade(null, null, Set.of(), new LinkedHashSet<>(
                    cves.stream().map(CveRecord::cveId).toList()));
        }
        Set<String> fixed = new LinkedHashSet<>();
        for (CveRecord c : cves) {
            if (!residual.contains(c.cveId())) fixed.add(c.cveId());
        }
        return new Upgrade(target, withVersion(cpe, target), fixed, residual);
    }
}

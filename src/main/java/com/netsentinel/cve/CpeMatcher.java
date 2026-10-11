package com.netsentinel.cve;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/**
 * CPE 2.3 matching with wildcard and version-range support.
 *
 * <p>An "affected" entry is a CPE 2.3 criteria string, optionally followed by a version
 * range suffix as produced from NVD {@code cpeMatch} nodes:
 * {@code cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*#>=2.4.0,<2.4.51}.
 * Supported range operators: {@code >=}, {@code >}, {@code <=}, {@code <}.</p>
 */
public final class CpeMatcher {

    private static final String RANGE_SEP = "#";

    private CpeMatcher() {}

    /** True if a concrete (scanned) CPE falls under the affected entry. */
    public static boolean matches(String queryCpe, String affected) {
        if (queryCpe == null || affected == null) return false;

        String criteria = affected;
        String range = "";
        int hash = affected.indexOf(RANGE_SEP);
        if (hash >= 0) {
            criteria = affected.substring(0, hash);
            range = affected.substring(hash + 1);
        }

        String[] q = queryCpe.split(":");
        String[] a = criteria.split(":");
        if (q.length < 6 || a.length < 6) return false;

        // part, vendor, product must match (wildcards allowed on the criteria side)
        for (int i = 2; i <= 4; i++) {
            if (!fieldMatches(q[i], a[i])) return false;
        }

        String queryVersion = q[5];
        if (!range.isEmpty()) {
            if (isAny(queryVersion)) return false; // cannot place an unknown version in a range
            if (!inRange(queryVersion, range)) return false;
        } else if (!fieldMatches(queryVersion, a[5])) {
            return false;
        }

        // update field (index 6), when both specify it
        if (q.length > 6 && a.length > 6 && !isAny(q[6]) && !isAny(a[6])) {
            return fieldMatches(q[6], a[6]);
        }
        return true;
    }

    /** Builds affected-CPE strings (with range suffixes) from an NVD CVE JSON node. */
    public static List<String> extractAffected(JsonNode cveNode) {
        List<String> out = new ArrayList<>();
        for (JsonNode config : cveNode.path("configurations")) {
            for (JsonNode node : config.path("nodes")) {
                for (JsonNode m : node.path("cpeMatch")) {
                    if (!m.path("vulnerable").asBoolean(true)) continue;
                    String criteria = m.path("criteria").asText("");
                    if (criteria.isEmpty()) continue;
                    List<String> bounds = new ArrayList<>();
                    addBound(bounds, ">=", m.path("versionStartIncluding"));
                    addBound(bounds, ">", m.path("versionStartExcluding"));
                    addBound(bounds, "<=", m.path("versionEndIncluding"));
                    addBound(bounds, "<", m.path("versionEndExcluding"));
                    out.add(bounds.isEmpty() ? criteria
                            : criteria + RANGE_SEP + String.join(",", bounds));
                }
            }
        }
        return out;
    }

    private static void addBound(List<String> bounds, String op, JsonNode v) {
        if (!v.isMissingNode() && !v.asText("").isEmpty()) bounds.add(op + v.asText());
    }

    /**
     * Outcome of checking one affected entry against a concrete CPE.
     *
     * @param affected whether the entry covers the CPE
     * @param fixedIn  smallest version that escapes this entry ({@code v + ".0.1"} means "any version after v"),
     *                 or null if no version of this entry's line is known to be fixed
     */
    public record Fix(boolean affected, String fixedIn) {}

    /** Version just above {@code v} that is below every real release after {@code v}. */
    public static String successor(String v) {
        return v + ".0.1";
    }

    /** True for versions produced by {@link #successor}; they mean "any release newer than the prefix". */
    public static boolean isSuccessor(String v) {
        return v.endsWith(".0.1");
    }

    public static Fix fixFor(String queryCpe, String affected) {
        if (!matches(queryCpe, affected)) return new Fix(false, null);
        String version = queryCpe.split(":")[5];
        int hash = affected.indexOf(RANGE_SEP);
        if (hash < 0) {
            String entryVersion = affected.substring(0, affected.length()).split(":")[5];
            // exact version entry: any other version is fine; wildcard: every version is affected
            return isAny(entryVersion) ? new Fix(true, null) : new Fix(true, successor(version));
        }
        for (String bound : affected.substring(hash + 1).split(",")) {
            if (bound.startsWith("<=")) return new Fix(true, successor(bound.substring(2)));
            if (bound.startsWith("<")) return new Fix(true, bound.substring(1));
        }
        return new Fix(true, null); // only a start bound: nothing newer is known to be fixed
    }

    private static boolean isAny(String f) {
        return f.equals("*") || f.equals("-") || f.isEmpty();
    }

    private static boolean fieldMatches(String query, String criteria) {
        if (criteria.equals("*")) return true;
        return query.equalsIgnoreCase(criteria);
    }

    private static boolean inRange(String version, String range) {
        for (String bound : range.split(",")) {
            String op;
            if (bound.startsWith(">=")) op = ">=";
            else if (bound.startsWith("<=")) op = "<=";
            else if (bound.startsWith(">")) op = ">";
            else if (bound.startsWith("<")) op = "<";
            else continue;
            int c = compareVersions(version, bound.substring(op.length()));
            boolean ok = switch (op) {
                case ">=" -> c >= 0;
                case ">" -> c > 0;
                case "<=" -> c <= 0;
                default -> c < 0;
            };
            if (!ok) return false;
        }
        return true;
    }

    /** Segment-wise version comparison; numeric segments compare numerically. */
    public static int compareVersions(String a, String b) {
        String[] x = a.split("[.\\-_]");
        String[] y = b.split("[.\\-_]");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            String s = i < x.length ? x[i] : "0";
            String t = i < y.length ? y[i] : "0";
            int c;
            if (isNumeric(s) && isNumeric(t)) {
                c = Long.compare(Long.parseLong(s), Long.parseLong(t));
            } else {
                c = s.compareToIgnoreCase(t);
            }
            if (c != 0) return c;
        }
        return 0;
    }

    private static boolean isNumeric(String s) {
        return !s.isEmpty() && s.chars().allMatch(Character::isDigit) && s.length() < 18;
    }
}

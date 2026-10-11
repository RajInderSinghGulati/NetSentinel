package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Tier 4: turns a chosen patch plan (from {@link PatchOptimizer}) into runnable artifacts.
 *
 * <p>Outputs are separate, clean documents so each can be linted and executed on its own:</p>
 * <ul>
 *   <li>{@code ansible}: a pure-YAML playbook, one play per host, FQCN modules only, idempotent
 *       package upgrades with service-restart handlers;</li>
 *   <li>{@code inventory}: INI inventory mapping the play hostnames to IPs;</li>
 *   <li>{@code bash}: an equivalent per-host script (apt/dnf);</li>
 *   <li>{@code report}: human-readable summary with the risk reduction and manual actions.</li>
 * </ul>
 *
 * <p>Only products that map to an OS package get an automated task. Application-level
 * dependencies (log4j, Spring Boot), Windows and vendor-repo products produce an explicit
 * {@code MANUAL} task instead of a guess.</p>
 */
@Component
public class RemediationGenerator {

    private static final Logger log = LoggerFactory.getLogger(RemediationGenerator.class);

    /** apt package, rpm package, service name (null = no service restart) per CPE product. */
    private record Pkg(String apt, String rpm, String aptService, String rpmService) {}

    private static final Map<String, Pkg> PACKAGES = Map.ofEntries(
            Map.entry("http_server", new Pkg("apache2", "httpd", "apache2", "httpd")),
            Map.entry("openssl", new Pkg("openssl", "openssl", null, null)),
            Map.entry("nginx", new Pkg("nginx", "nginx", "nginx", "nginx")),
            Map.entry("postfix", new Pkg("postfix", "postfix", "postfix", "postfix")),
            Map.entry("openvpn", new Pkg("openvpn", "openvpn", "openvpn", "openvpn")),
            Map.entry("tomcat", new Pkg("tomcat9", "tomcat", "tomcat9", "tomcat")),
            Map.entry("redis", new Pkg("redis-server", "redis", "redis-server", "redis")),
            Map.entry("postgresql", new Pkg("postgresql", "postgresql-server", "postgresql", "postgresql")),
            Map.entry("mongodb", new Pkg("mongodb-org", "mongodb-org", "mongod", "mongod")),
            Map.entry("elasticsearch", new Pkg("elasticsearch", "elasticsearch", "elasticsearch", "elasticsearch")),
            Map.entry("jenkins", new Pkg("jenkins", "jenkins", "jenkins", "jenkins"))
    );

    /** Generated artifacts for one patch plan. */
    public record Remediation(String ansible, String inventory, String bash, String report) {
        /** Single-document view (kept for API compatibility with older clients). */
        public String combined() {
            return report + "\n\n# ===== playbook.yml =====\n" + ansible
                    + "\n# ===== inventory.ini =====\n" + inventory
                    + "\n# ===== remediate.sh =====\n" + bash;
        }
    }

    public Remediation generate(List<PatchUnit> patches, String strategy, int budget,
                                double riskBefore, double riskAfter) {
        log.info("▶ Generating remediation for {} patch units ({} strategy)...", patches.size(), strategy);

        // group units by host, preserving plan order
        Map<String, List<PatchUnit>> byHost = new LinkedHashMap<>();
        for (PatchUnit u : patches) byHost.computeIfAbsent(u.hostId(), k -> new ArrayList<>()).add(u);

        Remediation r = new Remediation(
                ansible(byHost),
                inventory(byHost),
                bash(byHost),
                report(patches, byHost, strategy, budget, riskBefore, riskAfter));
        log.info("✓ Remediation generated: {} hosts, {} units", byHost.size(), patches.size());
        return r;
    }

    // ------------------------------------------------------------------ ansible

    private String ansible(Map<String, List<PatchUnit>> byHost) {
        StringBuilder sb = new StringBuilder();
        sb.append("---\n");
        sb.append("# NetSentinel-AI remediation playbook (generated ").append(LocalDate.now()).append(")\n");
        sb.append("# Review before running. Check mode first: ansible-playbook -i inventory.ini playbook.yml --check --diff\n");
        if (byHost.isEmpty()) {
            sb.append("[]\n");
            return sb.toString();
        }
        for (List<PatchUnit> units : byHost.values()) {
            PatchUnit first = units.get(0);
            sb.append("- name: \"Patch ").append(first.hostname()).append("\"\n");
            sb.append("  hosts: ").append(inventoryName(first)).append("\n");
            sb.append("  become: true\n");
            sb.append("  gather_facts: true\n");
            sb.append("  tasks:\n");
            List<String> handlers = new ArrayList<>();
            for (PatchUnit u : units) {
                String product = product(u.cpe());
                String version = version(u.cpe());
                String cves = cveSummary(u);
                Pkg pkg = PACKAGES.get(product);
                if (pkg != null && !isWindows(u) && u.fixesAnything()) {
                    String handler = "Restart " + product;
                    sb.append("    - name: \"Upgrade ").append(product).append(" ").append(version).append(" to ")
                            .append(toPhrase(u)).append(" (fixes ").append(cves).append(")\"  # noqa package-latest\n");
                    sb.append("      ansible.builtin.package:\n");
                    sb.append("        name: \"{{ '").append(pkg.apt()).append("' if ansible_os_family == 'Debian' else '")
                            .append(pkg.rpm()).append("' }}\"\n");
                    sb.append("        state: latest\n");
                    if (pkg.aptService() != null) {
                        sb.append("      notify: \"").append(handler).append("\"\n");
                        handlers.add(handler + "|" + pkg.aptService() + "|" + pkg.rpmService());
                    }
                } else {
                    sb.append("    - name: \"MANUAL - ").append(u.fixesAnything()
                                    ? "upgrade " + product + " " + version + " to " + toPhrase(u)
                                            + " (fixes " + cves + ")"
                                    : "no fixed release known for " + product + " " + version)
                            .append("\"\n");
                    sb.append("      ansible.builtin.debug:\n");
                    sb.append("        msg: \"").append(manualAdvice(u, product, version)).append("\"\n");
                }
            }
            if (!handlers.isEmpty()) {
                sb.append("  handlers:\n");
                for (String h : handlers.stream().distinct().toList()) {
                    String[] p = h.split("\\|");
                    sb.append("    - name: \"").append(p[0]).append("\"\n");
                    sb.append("      ansible.builtin.service:\n");
                    sb.append("        name: \"{{ '").append(p[1]).append("' if ansible_os_family == 'Debian' else '")
                            .append(p[2]).append("' }}\"\n");
                    sb.append("        state: restarted\n");
                }
            }
        }
        return sb.toString();
    }

    private String manualAdvice(PatchUnit u, String product, String version) {
        if (!u.fixesAnything()) {
            return "No release that fixes the known CVEs of " + product + " " + version
                    + " is known: apply vendor mitigations or restrict network access.";
        }
        if (isWindows(u)) {
            return "Windows host: update " + product + " " + version + " to " + toPhrase(u) + " via WSUS or the vendor installer.";
        }
        return switch (product) {
            case "log4j" -> "Application dependency: upgrade log4j-core to 2.17.1 or later in the application build and redeploy.";
            case "spring_boot" -> "Application dependency: upgrade Spring Boot in the application build and redeploy.";
            default -> "No OS package mapping for " + product + " " + version + ": upgrade to " + toPhrase(u) + " from the vendor repository or installer.";
        };
    }

    private String inventory(Map<String, List<PatchUnit>> byHost) {
        StringBuilder sb = new StringBuilder("[netsentinel_targets]\n");
        for (List<PatchUnit> units : byHost.values()) {
            PatchUnit u = units.get(0);
            sb.append(inventoryName(u)).append(" ansible_host=").append(u.hostId()).append("\n");
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ bash

    private String bash(Map<String, List<PatchUnit>> byHost) {
        StringBuilder sb = new StringBuilder();
        sb.append("#!/usr/bin/env bash\n");
        sb.append("# NetSentinel-AI remediation script. Run as root on each host; blocks apply only to the matching hostname.\n");
        sb.append("set -euo pipefail\n\n");
        sb.append("upgrade_pkg() {  # $1 = apt package, $2 = rpm package\n");
        sb.append("  if command -v apt-get >/dev/null 2>&1; then\n");
        sb.append("    apt-get update -qq\n");
        sb.append("    apt-get install -y --only-upgrade \"$1\"\n");
        sb.append("  else\n");
        sb.append("    dnf upgrade -y \"$2\"\n");
        sb.append("  fi\n");
        sb.append("}\n\n");
        sb.append("restart_svc() {  # $1 = apt service, $2 = rpm service\n");
        sb.append("  if command -v apt-get >/dev/null 2>&1; then systemctl restart \"$1\"; else systemctl restart \"$2\"; fi\n");
        sb.append("}\n\n");
        sb.append("HOST=\"$(hostname -s)\"\n\n");
        for (List<PatchUnit> units : byHost.values()) {
            PatchUnit first = units.get(0);
            sb.append("if [ \"$HOST\" = \"").append(first.hostname()).append("\" ]; then\n");
            for (PatchUnit u : units) {
                String product = product(u.cpe());
                Pkg pkg = PACKAGES.get(product);
                if (pkg != null && !isWindows(u) && u.fixesAnything()) {
                    sb.append("  echo \"[*] Upgrading ").append(product).append("\"\n");
                    sb.append("  upgrade_pkg \"").append(pkg.apt()).append("\" \"").append(pkg.rpm()).append("\"\n");
                    if (pkg.aptService() != null) {
                        sb.append("  restart_svc \"").append(pkg.aptService()).append("\" \"").append(pkg.rpmService()).append("\"\n");
                    }
                } else {
                    sb.append("  echo \"[!] MANUAL: ").append(manualAdvice(u, product, version(u.cpe()))).append("\"\n");
                }
            }
            sb.append("fi\n\n");
        }
        sb.append("echo \"Done. Re-run NetSentinel to confirm the attack paths are gone.\"\n");
        return sb.toString();
    }

    // ------------------------------------------------------------------ report

    private String report(List<PatchUnit> patches, Map<String, List<PatchUnit>> byHost, String strategy,
                          int budget, double before, double after) {
        StringBuilder sb = new StringBuilder();
        sb.append("NetSentinel-AI remediation plan\n");
        sb.append("===============================\n\n");
        sb.append("Strategy: ").append(strategy).append("   Budget: ").append(budget).append(" patches\n");
        sb.append(String.format("Crown-jewel risk: %.4f -> %.4f", before, after));
        if (before > 0) sb.append(String.format("  (%.1f%% reduction)", 100.0 * (1.0 - after / before)));
        sb.append("\n");
        sb.append("Risk = criticality-weighted expected number of compromised crown jewels, counting known CVEs only.\n\n");
        sb.append("Patches (apply in this order)\n-----------------------------\n");
        int i = 1;
        for (PatchUnit u : patches) {
            sb.append(String.format("%d. %s%n", i++, u.upgradeSummary()));
            sb.append("     fixes: ").append(cveSummary(u)).append(String.format("  (highest CVSS %.1f)%n", u.maxCvss()));
            if (!u.residualCves().isEmpty()) {
                sb.append("     still affected after upgrade: ").append(u.residualCves().size()).append(" CVEs\n");
            }
            if (!u.introduced().isEmpty()) {
                sb.append("     newly affecting the target version: ").append(u.introduced().size()).append(" CVEs\n");
            }
            Pkg pkg = PACKAGES.get(product(u.cpe()));
            sb.append("     ").append(pkg != null && !isWindows(u) && u.fixesAnything()
                    ? "automated (package upgrade; confirm the repository offers " + toPhrase(u) + ")"
                    : "MANUAL action required").append("\n");
        }
        long manual = patches.stream()
                .filter(u -> PACKAGES.get(product(u.cpe())) == null || isWindows(u) || !u.fixesAnything()).count();
        sb.append("\n").append(manual).append(" of ").append(patches.size()).append(" patches need manual action.\n");
        sb.append("\nVerification\n------------\n");
        sb.append("1. ansible-playbook -i inventory.ini playbook.yml --check --diff\n");
        sb.append("2. Apply, then re-run the NetSentinel scan (GET /api/scan/{id}/verify simulates this).\n");
        sb.append("3. Confirm service availability on: ")
                .append(byHost.values().stream().map(l -> l.get(0).hostname()).collect(Collectors.joining(", ")))
                .append("\n");
        return sb.toString();
    }

    // ------------------------------------------------------------------ helpers

    static String product(String cpe) {
        String[] p = cpe.split(":");
        return p.length > 4 ? p[4] : cpe;
    }

    static String version(String cpe) {
        String[] p = cpe.split(":");
        return p.length > 5 ? p[5] : "";
    }

    private static boolean isWindows(PatchUnit u) {
        return "microsoft".equals(u.cpe().split(":").length > 3 ? u.cpe().split(":")[3] : "");
    }

    /** Hostname usable as an Ansible inventory name. */
    private static String inventoryName(PatchUnit u) {
        return u.hostname().replaceAll("[^A-Za-z0-9_]", "_");
    }

    /** "version 8.6.3" or "a release newer than 2.4.50". */
    private static String toPhrase(PatchUnit u) {
        if (u.targetVersion() == null) return u.targetLabel();
        return com.netsentinel.cve.CpeMatcher.isSuccessor(u.targetVersion())
                ? "a release " + u.targetLabel() : "version " + u.targetVersion();
    }

    private static String cveSummary(PatchUnit u) {
        List<CveRecord> fixed = u.fixedCves();
        if (fixed.isEmpty()) return "no CVEs";
        List<String> ids = fixed.stream()
                .sorted(Comparator.comparingDouble(CveRecord::cvssBaseScore).reversed())
                .map(CveRecord::cveId).distinct().limit(3).toList();
        int total = (int) fixed.stream().map(CveRecord::cveId).distinct().count();
        return String.join(", ", ids) + (total > ids.size() ? " +" + (total - ids.size()) + " more" : "");
    }
}

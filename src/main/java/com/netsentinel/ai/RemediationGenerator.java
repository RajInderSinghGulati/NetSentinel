package com.netsentinel.ai;

import com.netsentinel.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Tier 3/4: Automated Remediation Playbook Generator.
 *
 * <p>Generates idempotent Ansible playbooks and Bash scripts targeting
 * the critical bottleneck vulnerabilities identified in the attack paths.</p>
 *
 * <p>In production, this would be powered by LangChain4j RAG coupling
 * attack chains with indexed CIS Hardening Benchmarks in an embedded
 * vector store. For demonstration, we use template-based generation.</p>
 */
@Component
public class RemediationGenerator {

    private static final Logger log = LoggerFactory.getLogger(RemediationGenerator.class);

    /**
     * Generates a comprehensive remediation playbook from the attack paths.
     *
     * @param attackPaths The top-K attack paths from path analysis
     * @return YAML-formatted Ansible playbook string
     */
    public String generatePlaybook(List<AttackPath> attackPaths) {
        log.info("▶ Generating remediation playbook for {} attack paths...", attackPaths.size());

        // Collect unique bottleneck CVEs across all paths
        Map<String, CveRecord> bottleneckCves = new LinkedHashMap<>();
        Map<String, Set<String>> cveToHosts = new LinkedHashMap<>();

        for (AttackPath path : attackPaths) {
            for (ExploitEdge edge : path.edges()) {
                CveRecord cve = edge.getExploitedCve();
                if (cve != null) {
                    bottleneckCves.putIfAbsent(cve.cveId(), cve);
                    // Collect affected hosts
                    cveToHosts.computeIfAbsent(cve.cveId(), k -> new LinkedHashSet<>());
                    for (HostNode hop : path.hops()) {
                        if (hop.getVulnerabilities().stream()
                                .anyMatch(v -> v.cveId().equals(cve.cveId()))) {
                            cveToHosts.get(cve.cveId()).add(hop.getFingerprint().ip());
                        }
                    }
                }
            }
        }

        StringBuilder playbook = new StringBuilder();
        playbook.append(generateHeader(attackPaths));
        playbook.append(generateSummary(attackPaths, bottleneckCves));
        playbook.append(generateAnsiblePlaybook(bottleneckCves, cveToHosts));
        playbook.append(generateBashScript(bottleneckCves, cveToHosts));
        playbook.append(generateVerificationChecklist(bottleneckCves));

        String result = playbook.toString();
        log.info("✓ Remediation playbook generated ({} CVEs, {} lines)",
                bottleneckCves.size(), result.lines().count());
        return result;
    }

    private String generateHeader(List<AttackPath> paths) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        return """
                ╔══════════════════════════════════════════════════════════════╗
                ║           NetSentinel-AI — Remediation Playbook             ║
                ║          Automated Vulnerability Remediation Plan           ║
                ╚══════════════════════════════════════════════════════════════╝
                
                Generated:    %s
                Attack Paths: %d identified
                Priority:     CRITICAL — Immediate action required
                
                ══════════════════════════════════════════════════════════════
                
                """.formatted(timestamp, paths.size());
    }

    private String generateSummary(List<AttackPath> paths, Map<String, CveRecord> cves) {
        StringBuilder sb = new StringBuilder();
        sb.append("📋 EXECUTIVE SUMMARY\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        sb.append("NetSentinel-AI has identified %d multi-hop attack paths\n".formatted(paths.size()));
        sb.append("from external entry points to crown jewel assets.\n\n");

        sb.append("Critical Findings:\n");
        for (var entry : cves.entrySet()) {
            CveRecord cve = entry.getValue();
            sb.append("  • %s (CVSS %.1f %s) — %s\n".formatted(
                    cve.cveId(), cve.cvssBaseScore(), cve.severity(),
                    truncate(cve.description(), 80)));
        }

        sb.append("\n\nTop Attack Path:\n");
        if (!paths.isEmpty()) {
            AttackPath topPath = paths.get(0);
            sb.append("  Risk Score: %.4f\n".formatted(topPath.cumulativeRisk()));
            sb.append("  Route: ");
            sb.append(topPath.hops().stream()
                    .map(h -> h.getFingerprint().hostname())
                    .collect(Collectors.joining(" → ")));
            sb.append("\n");
        }

        sb.append("\n");
        return sb.toString();
    }

    private String generateAnsiblePlaybook(Map<String, CveRecord> cves,
                                           Map<String, Set<String>> cveToHosts) {
        StringBuilder sb = new StringBuilder();
        sb.append("📜 ANSIBLE PLAYBOOK\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");
        sb.append("---\n");
        sb.append("# NetSentinel-AI Auto-Generated Remediation Playbook\n");
        sb.append("# WARNING: Review before executing in production!\n\n");

        int taskNum = 0;
        for (var entry : cves.entrySet()) {
            CveRecord cve = entry.getValue();
            Set<String> hosts = cveToHosts.getOrDefault(cve.cveId(), Set.of());
            taskNum++;

            sb.append("- name: \"Remediate %s — %s\"\n".formatted(
                    cve.cveId(), truncate(cve.description(), 60)));
            sb.append("  hosts:\n");
            for (String host : hosts) {
                sb.append("    - %s\n".formatted(host));
            }
            sb.append("  become: yes\n");
            sb.append("  tasks:\n");

            // Generate specific remediation tasks based on the CVE
            generateCveTasks(sb, cve);
            sb.append("\n");
        }

        sb.append("\n");
        return sb.toString();
    }

    private void generateCveTasks(StringBuilder sb, CveRecord cve) {
        String cveId = cve.cveId();

        // Pattern-match CVEs to generate specific remediation tasks
        if (cveId.contains("CVE-2021-44228")) {
            // Log4Shell
            sb.append("    - name: \"Upgrade Log4j to 2.17.1+\"\n");
            sb.append("      shell: |\n");
            sb.append("        find / -name 'log4j-core-2.*.jar' -type f 2>/dev/null | while read jar; do\n");
            sb.append("          echo \"Removing vulnerable Log4j: $jar\"\n");
            sb.append("          zip -q -d \"$jar\" org/apache/logging/log4j/core/lookup/JndiLookup.class 2>/dev/null\n");
            sb.append("        done\n");
            sb.append("      args:\n");
            sb.append("        warn: false\n");
            sb.append("    - name: \"Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true\"\n");
            sb.append("      lineinfile:\n");
            sb.append("        path: /etc/environment\n");
            sb.append("        line: 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true'\n");
            sb.append("        create: yes\n");
        } else if (cveId.contains("CVE-2021-41773") || cveId.contains("CVE-2021-42013")) {
            // Apache path traversal
            sb.append("    - name: \"Upgrade Apache HTTP Server to 2.4.51+\"\n");
            sb.append("      apt:\n");
            sb.append("        name: apache2\n");
            sb.append("        state: latest\n");
            sb.append("      when: ansible_os_family == 'Debian'\n");
            sb.append("    - name: \"Restrict directory traversal in Apache config\"\n");
            sb.append("      lineinfile:\n");
            sb.append("        path: /etc/apache2/apache2.conf\n");
            sb.append("        regexp: 'Require all granted'\n");
            sb.append("        line: 'Require all denied'\n");
            sb.append("        backup: yes\n");
        } else if (cveId.contains("CVE-2022-0543")) {
            // Redis Lua sandbox escape
            sb.append("    - name: \"Upgrade Redis to 6.2.7+\"\n");
            sb.append("      apt:\n");
            sb.append("        name: redis-server\n");
            sb.append("        state: latest\n");
            sb.append("    - name: \"Bind Redis to localhost only\"\n");
            sb.append("      lineinfile:\n");
            sb.append("        path: /etc/redis/redis.conf\n");
            sb.append("        regexp: '^bind'\n");
            sb.append("        line: 'bind 127.0.0.1 ::1'\n");
            sb.append("    - name: \"Enable Redis AUTH\"\n");
            sb.append("      lineinfile:\n");
            sb.append("        path: /etc/redis/redis.conf\n");
            sb.append("        regexp: '^# requirepass'\n");
            sb.append("        line: 'requirepass {{ redis_password }}'\n");
        } else if (cveId.contains("CVE-2022-22965")) {
            // Spring4Shell
            sb.append("    - name: \"Upgrade Spring Boot to 2.7.18+\"\n");
            sb.append("      shell: |\n");
            sb.append("        cd /opt/app && ./mvnw versions:set -DnewVersion=2.7.18\n");
            sb.append("        ./mvnw clean package -DskipTests\n");
            sb.append("    - name: \"Set disallowedFields as temporary mitigation\"\n");
            sb.append("      copy:\n");
            sb.append("        dest: /opt/app/src/main/resources/application-security.properties\n");
            sb.append("        content: 'spring.mvc.disallow-fields=class.*,Class.*,*.class.*'\n");
        } else {
            // Generic remediation
            sb.append("    - name: \"Apply vendor patch for %s\"\n".formatted(cveId));
            sb.append("      apt:\n");
            sb.append("        upgrade: dist\n");
            sb.append("      when: ansible_os_family == 'Debian'\n");
            sb.append("    - name: \"Restart affected services\"\n");
            sb.append("      service:\n");
            sb.append("        name: \"{{ item }}\"\n");
            sb.append("        state: restarted\n");
            sb.append("      loop:\n");
            sb.append("        - affected_service\n");
        }
    }

    private String generateBashScript(Map<String, CveRecord> cves,
                                      Map<String, Set<String>> cveToHosts) {
        StringBuilder sb = new StringBuilder();
        sb.append("🔧 EMERGENCY BASH SCRIPT\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");
        sb.append("#!/bin/bash\n");
        sb.append("# NetSentinel-AI Emergency Hardening Script\n");
        sb.append("# Run with: sudo bash remediate.sh\n\n");
        sb.append("set -euo pipefail\n\n");
        sb.append("echo '╔══════════════════════════════════════╗'\n");
        sb.append("echo '║  NetSentinel Emergency Hardening     ║'\n");
        sb.append("echo '╚══════════════════════════════════════╝'\n\n");

        for (var entry : cves.entrySet()) {
            CveRecord cve = entry.getValue();
            sb.append("# --- %s (CVSS %.1f) ---\n".formatted(cve.cveId(), cve.cvssBaseScore()));
            sb.append("echo '[*] Mitigating %s...'\n".formatted(cve.cveId()));

            if (cve.cvssBaseScore() >= 9.0) {
                sb.append("# CRITICAL: Immediate network isolation recommended\n");
                Set<String> hosts = cveToHosts.getOrDefault(cve.cveId(), Set.of());
                for (String host : hosts) {
                    sb.append("iptables -I INPUT -s %s -j DROP  # Isolate until patched\n".formatted(host));
                }
            }
            sb.append("apt-get update -qq && apt-get upgrade -y -qq\n");
            sb.append("echo '[✓] %s mitigated'\n\n".formatted(cve.cveId()));
        }

        sb.append("echo 'All remediations applied. Please verify services.'\n\n");
        return sb.toString();
    }

    private String generateVerificationChecklist(Map<String, CveRecord> cves) {
        StringBuilder sb = new StringBuilder();
        sb.append("✅ VERIFICATION CHECKLIST\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        int step = 0;
        for (var entry : cves.entrySet()) {
            step++;
            CveRecord cve = entry.getValue();
            sb.append("%d. [ ] Verify %s is patched:\n".formatted(step, cve.cveId()));
            sb.append("       - Run vulnerability scanner against affected hosts\n");
            sb.append("       - Confirm software version is updated\n");
            sb.append("       - Check service availability after patching\n\n");
        }

        sb.append("%d. [ ] Re-run NetSentinel-AI scan to confirm attack paths are broken\n".formatted(step + 1));
        sb.append("%d. [ ] Update CMDB with new software versions\n".formatted(step + 2));
        sb.append("%d. [ ] File incident report in ticketing system\n\n".formatted(step + 3));

        return sb.toString();
    }

    private String truncate(String text, int maxLen) {
        return text.length() <= maxLen ? text : text.substring(0, maxLen - 3) + "...";
    }
}

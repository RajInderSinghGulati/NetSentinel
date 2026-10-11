package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;
import com.netsentinel.model.CveRecord.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Simulated CVE database pre-loaded with ~20 real-world vulnerabilities
 * mapped to the software versions in our simulated network.
 *
 * <p>In production, this would be replaced by an NVD REST API client
 * using Java 21 {@code HttpClient} with async queries.</p>
 */
@Component("simulatedCveDb")
public class SimulatedCveDatabase implements CveDatabase {

    private static final Logger log = LoggerFactory.getLogger(SimulatedCveDatabase.class);
    private final List<CveRecord> cveRecords;

    public SimulatedCveDatabase() {
        this.cveRecords = buildCveDatabase();
        log.info("✓ Loaded {} CVE records into simulated database", cveRecords.size());
    }

    @Override
    public List<CveRecord> findByCpe(String cpeString) {
        return cveRecords.stream()
                .filter(cve -> cve.affectedCpes().stream()
                        .anyMatch(affectedCpe -> cpeMatches(cpeString, affectedCpe)))
                .collect(Collectors.toList());
    }

    @Override
    public List<CveRecord> findAll() {
        return List.copyOf(cveRecords);
    }

    /**
     * Simple CPE matching: checks if the queried CPE starts with the
     * affected CPE prefix (vendor:product:version match).
     */
    private boolean cpeMatches(String queryCpe, String affectedCpe) {
        return CpeMatcher.matches(queryCpe, affectedCpe);
    }

    /**
     * Builds the simulated CVE database with real-world vulnerabilities.
     */
    private List<CveRecord> buildCveDatabase() {
        List<CveRecord> cves = new ArrayList<>();

        // ══════════════════════════════════════════════
        // Apache HTTP Server CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-41773",
                "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49. " +
                "A flaw in path normalization allows an attacker to map URLs to files outside " +
                "the directories configured by Alias-like directives.",
                7.5, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-22",
                List.of("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
                true, true
        ));

        cves.add(new CveRecord(
                "CVE-2021-42013",
                "Path traversal and RCE in Apache HTTP Server 2.4.49 and 2.4.50. " +
                "The fix for CVE-2021-41773 was insufficient, allowing remote code execution " +
                "when mod_cgi is enabled.",
                9.8, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-22",
                List.of("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
                true, true
        ));

        // ══════════════════════════════════════════════
        // Log4j (Log4Shell) — affects Spring Boot app
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-44228",
                "Apache Log4j2 JNDI RCE (Log4Shell). A critical remote code execution " +
                "vulnerability in Log4j 2.x allowing attackers to execute arbitrary code " +
                "via crafted log messages containing JNDI lookup expressions.",
                10.0, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-502",
                List.of("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
                true, true
        ));

        // ══════════════════════════════════════════════
        // Apache Tomcat CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-33037",
                "Apache Tomcat HTTP request smuggling via improper handling of Transfer-Encoding " +
                "headers, allowing attackers to poison web caches or bypass security controls.",
                5.3, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-444",
                List.of("cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"),
                true, false
        ));

        cves.add(new CveRecord(
                "CVE-2022-23181",
                "Apache Tomcat local privilege escalation via a time-of-check time-of-use " +
                "race condition when configured to persist sessions using FileStore.",
                7.0, AttackVector.LOCAL, AttackComplexity.HIGH,
                PrivilegesRequired.LOW, UserInteraction.NONE,
                "CWE-367",
                List.of("cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // Jenkins CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-27925",
                "Jenkins arbitrary file read vulnerability allowing unauthenticated attackers " +
                "to read arbitrary files from the Jenkins controller file system.",
                7.5, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-22",
                List.of("cpe:2.3:a:jenkins:jenkins:2.346.1:*:*:*:*:*:*:*"),
                true, true
        ));

        // ══════════════════════════════════════════════
        // PostgreSQL CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-23214",
                "PostgreSQL server processes unencrypted bytes from a man-in-the-middle attacker " +
                "as SSL-encrypted data. An active MITM can inject SQL commands during the initial " +
                "setup of an SSL connection.",
                8.1, AttackVector.NETWORK, AttackComplexity.HIGH,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-89",
                List.of("cpe:2.3:a:postgresql:postgresql:13.3:*:*:*:*:*:*:*"),
                true, false
        ));

        cves.add(new CveRecord(
                "CVE-2022-1552",
                "PostgreSQL autovacuum and REINDEX privilege escalation allows any user to " +
                "execute arbitrary SQL functions under a superuser identity.",
                8.8, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.LOW, UserInteraction.NONE,
                "CWE-459",
                List.of("cpe:2.3:a:postgresql:postgresql:13.3:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // MongoDB CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-32040",
                "MongoDB Server DoS vulnerability. Specially crafted aggregation pipeline queries " +
                "can cause the server to consume excessive memory leading to denial of service.",
                7.5, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-400",
                List.of("cpe:2.3:a:mongodb:mongodb:5.0.3:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // Redis CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-0543",
                "Redis Lua sandbox escape. Due to a packaging issue in Debian/Ubuntu, the Lua " +
                "library in Redis can be used to execute arbitrary OS commands.",
                10.0, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-862",
                List.of("cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*"),
                true, true
        ));

        // ══════════════════════════════════════════════
        // Elasticsearch CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-22145",
                "Elasticsearch information disclosure. A specially crafted request to the " +
                "_async_search API can lead to disclosure of internal cluster information.",
                6.5, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.LOW, UserInteraction.NONE,
                "CWE-200",
                List.of("cpe:2.3:a:elastic:elasticsearch:7.17.0:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // OpenSSL CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-0778",
                "OpenSSL infinite loop DoS in BN_mod_sqrt(). Crafted certificates can cause " +
                "the server to enter an infinite loop, resulting in denial of service.",
                7.5, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-835",
                List.of("cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // MSSQL Server CVEs (Crown Jewel target)
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-29143",
                "Microsoft SQL Server Remote Code Execution via SQL Server Agent job step. " +
                "An authenticated attacker can execute arbitrary code on the server.",
                7.5, AttackVector.NETWORK, AttackComplexity.HIGH,
                PrivilegesRequired.LOW, UserInteraction.NONE,
                "CWE-284",
                List.of("cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // SAP NetWeaver (Crown Jewel target)
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-22536",
                "SAP NetWeaver request smuggling and HTTP desync via ICM component. Allows " +
                "unauthenticated attackers to prepend victim requests with arbitrary data.",
                10.0, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-444",
                List.of("cpe:2.3:a:sap:netweaver:7.50:*:*:*:*:*:*:*"),
                true, true
        ));

        // ══════════════════════════════════════════════
        // HashiCorp Vault CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-36129",
                "HashiCorp Vault privilege escalation via entity alias metadata. Certain " +
                "auth methods allow an attacker to gain access to secrets beyond their policy.",
                8.6, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-269",
                List.of("cpe:2.3:a:hashicorp:vault:1.11.3:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // Nginx CVEs
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2021-23017",
                "Nginx DNS resolver off-by-one heap write. A specially crafted DNS response " +
                "can overwrite heap memory, potentially leading to remote code execution.",
                7.7, AttackVector.NETWORK, AttackComplexity.HIGH,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-193",
                List.of("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"),
                true, false
        ));

        // ══════════════════════════════════════════════
        // Spring Boot / Spring Framework
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-22965",
                "Spring4Shell — Spring Framework RCE via data binding to ClassLoader. " +
                "Allows unauthenticated attackers to execute arbitrary commands on JDK 9+ " +
                "when running on Apache Tomcat.",
                9.8, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-94",
                List.of("cpe:2.3:a:vmware:spring_boot:2.7.5:*:*:*:*:*:*:*"),
                true, true
        ));

        // ══════════════════════════════════════════════
        // OpenVPN
        // ══════════════════════════════════════════════
        cves.add(new CveRecord(
                "CVE-2022-0547",
                "OpenVPN authentication bypass with deferred authentication. Allows " +
                "unauthenticated clients to bypass authentication and connect to the VPN.",
                9.8, AttackVector.NETWORK, AttackComplexity.LOW,
                PrivilegesRequired.NONE, UserInteraction.NONE,
                "CWE-305",
                List.of("cpe:2.3:a:openvpn:openvpn:2.5.1:*:*:*:*:*:*:*"),
                true, false
        ));

        return cves;
    }
}

package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** Structural lint of the generated playbook (real ansible-lint is run by scripts/validate_remediation.*). */
class RemediationGeneratorTest {

    private final RemediationGenerator generator = new RemediationGenerator();

    private static PatchUnit unit(int i, String ip, String host, String cpe, CveRecord... cves) {
        return new PatchUnit(i, ip, host, cpe, List.of(cves));
    }

    private List<PatchUnit> sample() {
        return List.of(
                unit(0, "10.0.1.5", "web-server-01", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                        RiskModelTest.cve("CVE-2021-41773", 7.5), RiskModelTest.cve("CVE-2021-42013", 9.8)),
                unit(1, "10.0.2.9", "cache-redis", "cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*",
                        RiskModelTest.cve("CVE-2022-0543", 10.0)),
                unit(2, "10.0.1.5", "web-server-01", "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
                        RiskModelTest.cve("CVE-2022-0778", 7.5)),
                unit(3, "10.0.3.7", "app-server-spring", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                        RiskModelTest.cve("CVE-2021-44228", 10.0)),
                unit(4, "10.0.4.2", "hr-database", "cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*",
                        RiskModelTest.cve("CVE-2024-0001", 8.8)));
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> parsePlays(String yaml) {
        Object doc = new Yaml().load(yaml);
        assertInstanceOf(List.class, doc, "playbook must be a YAML list of plays");
        return (List<Map<String, Object>>) doc;
    }

    /** Shared assertions, also used on the real pipeline output. */
    @SuppressWarnings("unchecked")
    static void assertPlaybookWellFormed(String yaml, String inventory) {
        Set<String> allowedModules = Set.of("ansible.builtin.package", "ansible.builtin.debug");
        for (Map<String, Object> play : parsePlays(yaml)) {
            assertTrue(play.keySet().containsAll(List.of("name", "hosts", "become", "tasks")), "play keys: " + play.keySet());
            assertTrue(inventory.contains((String) play.get("hosts")), "host missing from inventory: " + play.get("hosts"));

            Set<String> handlerNames = new HashSet<>();
            for (Map<String, Object> h : (List<Map<String, Object>>) play.getOrDefault("handlers", List.of())) {
                assertTrue(h.containsKey("name"));
                assertTrue(h.containsKey("ansible.builtin.service"));
                handlerNames.add((String) h.get("name"));
            }
            for (Map<String, Object> task : (List<Map<String, Object>>) play.get("tasks")) {
                assertNotNull(task.get("name"), "every task needs a name");
                assertTrue(Character.isUpperCase(((String) task.get("name")).charAt(0)), "task names start upper-case");
                Set<String> keys = new HashSet<>(task.keySet());
                keys.removeAll(Set.of("name", "notify"));
                assertEquals(1, keys.size(), "exactly one module per task: " + task.keySet());
                assertTrue(allowedModules.contains(keys.iterator().next()), "unexpected module " + keys);
                assertFalse(task.containsKey("shell") || task.containsKey("command"), "no raw shell/command tasks");
                if (task.containsKey("ansible.builtin.package")) {
                    assertEquals("latest", ((Map<String, Object>) task.get("ansible.builtin.package")).get("state"));
                }
                if (task.containsKey("notify")) {
                    assertTrue(handlerNames.contains((String) task.get("notify")), "notify without handler: " + task.get("notify"));
                }
            }
        }
    }

    @Test
    void playbookIsWellFormedAndGroupedByHost() {
        var r = generator.generate(sample(), "OPTIMAL", 5, 1.27, 0.08);
        assertPlaybookWellFormed(r.ansible(), r.inventory());

        var plays = parsePlays(r.ansible());
        assertEquals(4, plays.size(), "two units on web-server-01 share one play");
        assertEquals("web_server_01", plays.get(0).get("hosts"));
        assertEquals(2, ((List<?>) plays.get(0).get("tasks")).size());
        assertTrue(r.inventory().contains("web_server_01 ansible_host=10.0.1.5"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void unmappedProductsBecomeExplicitManualTasks() {
        var r = generator.generate(sample(), "OPTIMAL", 5, 1.0, 0.5);
        String yaml = r.ansible();
        assertTrue(yaml.contains("MANUAL - upgrade log4j"));
        assertTrue(yaml.contains("MANUAL - upgrade sql_server"));
        assertTrue(yaml.contains("Windows host"));
        // redis and apache are automated
        assertTrue(yaml.contains("ansible.builtin.package"));
        assertTrue(r.report().contains("2 of 5 patches need manual action") || r.report().contains("3 of 5 patches need manual action"));
        assertTrue(r.bash().contains("set -euo pipefail"));
        assertTrue(r.bash().contains("[ \"$HOST\" = \"cache-redis\" ]"));
    }

    @Test
    void emptyPlanIsStillValidYaml() {
        var r = generator.generate(List.of(), "GREEDY", 0, 0.0, 0.0);
        assertTrue(parsePlays(r.ansible()).isEmpty());
        assertTrue(r.report().contains("0 of 0"));
    }

    @Test
    void reportStatesRiskReduction() {
        var r = generator.generate(sample(), "OPTIMAL", 5, 1.0, 0.25);
        assertTrue(r.report().contains("1.0000 -> 0.2500"));
        assertTrue(r.report().contains("75.0% reduction"));
    }
}

package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UpgradePlannerTest {

    private static final String CPE = "cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*";

    private static CveRecord cve(String id, String... entries) {
        return new CveRecord(id, id, 7.0, CveRecord.AttackVector.NETWORK, CveRecord.AttackComplexity.LOW,
                CveRecord.PrivilegesRequired.NONE, CveRecord.UserInteraction.NONE, "CWE-1",
                List.of(entries), true, false);
    }

    private static String range(String bounds) {
        return "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*#" + bounds;
    }

    @Test
    void fixFor() {
        assertEquals(new CpeMatcher.Fix(false, null), CpeMatcher.fixFor(CPE, range(">=7.0,<7.2")));
        assertEquals("6.2.7", CpeMatcher.fixFor(CPE, range("<6.2.7")).fixedIn());
        assertEquals("6.2.6.0.1", CpeMatcher.fixFor(CPE, range("<=6.2.6")).fixedIn());
        assertNull(CpeMatcher.fixFor(CPE, range(">=6.0")).fixedIn(), "start bound only: no known fix");
        assertNull(CpeMatcher.fixFor(CPE, "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*").fixedIn(), "all versions");
        assertEquals("6.2.6.0.1", CpeMatcher.fixFor(CPE, CPE).fixedIn(), "exact version entry");
    }

    @Test
    void picksSmallestVersionThatFixesEverythingFixable() {
        var up = UpgradePlanner.plan(CPE, List.of(
                cve("A", range("<6.2.7")),
                cve("B", range("<6.2.14")),
                cve("C", range(">=6.0,<7.0.5"))));
        assertEquals("7.0.5", up.targetVersion());
        assertEquals("cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*", up.targetCpe());
        assertEquals(java.util.Set.of("A", "B", "C"), up.fixedCveIds());
        assertTrue(up.residualCveIds().isEmpty());
    }

    @Test
    void unfixableCvesAreResidual() {
        var up = UpgradePlanner.plan(CPE, List.of(
                cve("A", range("<6.2.7")),
                cve("ALL", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
                cve("OPEN", range(">=6.0"))));
        assertEquals("6.2.7", up.targetVersion());
        assertEquals(java.util.Set.of("A"), up.fixedCveIds());
        assertEquals(java.util.Set.of("ALL", "OPEN"), up.residualCveIds());
    }

    @Test
    void nothingFixableMeansNoTarget() {
        var up = UpgradePlanner.plan(CPE, List.of(cve("ALL", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*")));
        assertFalse(up.hasTarget());
        assertEquals("no fix known", up.targetLabel());
        assertEquals(java.util.Set.of("ALL"), up.residualCveIds());
    }

    @Test
    void chainsAcrossAffectedRanges() {
        // fixed in 6.2.7, but 6.2.7-6.2.9 is again affected until 6.2.10 (a second CVE range)
        var up = UpgradePlanner.plan(CPE, List.of(
                cve("A", range("<6.2.7")),
                cve("B", range(">=6.2.7,<6.2.10")),
                cve("C", range("<6.2.9"))));
        assertEquals("6.2.10", up.targetVersion());
    }

    @Test
    void hexExactVersionAndRecordsWithoutRangeDataAreFixedByAnyUpgrade() {
        var exact = UpgradePlanner.plan(CPE, List.of(cve("E", CPE)));
        assertEquals("6.2.6.0.1", exact.targetVersion());
        assertEquals("newer than 6.2.6", exact.targetLabel());

        // hand-written record whose CPE list names another product: no range info, assume fixed by upgrading
        var synthetic = UpgradePlanner.plan(CPE, List.of(cve("S", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*")));
        assertEquals("6.2.6.0.1", synthetic.targetVersion());
        assertEquals(java.util.Set.of("S"), synthetic.fixedCveIds());
    }

    @Test
    void targetVersionOrderingHelpers() {
        assertTrue(CpeMatcher.compareVersions("6.2.6.0.1", "6.2.6") > 0);
        assertTrue(CpeMatcher.compareVersions("6.2.6.0.1", "6.2.7") < 0);
        assertTrue(CpeMatcher.isSuccessor("6.2.6.0.1"));
        assertFalse(CpeMatcher.isSuccessor("6.2.7"));
    }
}

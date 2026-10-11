package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Checks the pinned snapshot loads and that real NVD range data matches correctly. */
class OfflineNvdCveDatabaseTest {

    private static OfflineNvdCveDatabase db;

    @BeforeAll
    static void load() {
        db = new OfflineNvdCveDatabase(new NvdApiClient(), "");
    }

    @Test
    void snapshotLoaded() {
        assertFalse(db.isEmpty(), "run scripts/fetch_nvd_snapshot.py first");
    }

    @Test
    void log4shellMatchesVulnerableVersionOnly() {
        List<CveRecord> vuln = db.findByCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
        assertTrue(vuln.stream().anyMatch(c -> c.cveId().equals("CVE-2021-44228")));

        List<CveRecord> fixed = db.findByCpe("cpe:2.3:a:apache:log4j:2.17.2:*:*:*:*:*:*:*");
        assertTrue(fixed.stream().noneMatch(c -> c.cveId().equals("CVE-2021-44228")));
    }

    @Test
    void recordsCarryYearAndVendor() {
        CveRecord r = db.findByCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").stream()
                .filter(c -> c.cveId().equals("CVE-2021-44228")).findFirst().orElseThrow();
        assertEquals(2021, r.publishedYear());
        // Feature parity with scripts/build_dataset.py (values checked against data/cve_features.csv)
        assertEquals("cisco", r.vendor());
        assertEquals("CWE-20", r.cweId());
        assertEquals("CHANGED", r.scope());
        assertEquals(373, r.affectedCpes().size());
    }

    @Test
    void cweSkipsNvdPlaceholdersLikeTheTrainingPipeline() {
        CveRecord r = db.findAll().stream().filter(c -> c.cveId().equals("CVE-2023-44487")).findFirst().orElseThrow();
        assertEquals("CWE-400", r.cweId()); // first weakness entry is NVD-CWE-noinfo
    }
}

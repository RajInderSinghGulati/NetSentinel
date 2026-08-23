package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;

import java.util.List;

/**
 * Pluggable CVE database interface for Tier 2: CVE Ingestion.
 *
 * <p>Implementations look up known vulnerabilities by CPE string,
 * sourced from the NVD REST API or a local cache.</p>
 */
public interface CveDatabase {

    /**
     * Finds CVE records matching the given CPE string.
     *
     * @param cpeString CPE 2.3 formatted string (e.g., "cpe:2.3:a:apache:http_server:2.4.49:...")
     * @return List of matching CVE records, empty if none found
     */
    List<CveRecord> findByCpe(String cpeString);

    /**
     * Returns all CVEs in the database.
     */
    List<CveRecord> findAll();
}

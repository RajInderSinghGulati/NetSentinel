package com.netsentinel.cve;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netsentinel.model.CveRecord;
import com.netsentinel.model.CveRecord.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Tier 2: Async NVD REST API v2 CVE Client.
 *
 * <p>Queries the NIST National Vulnerability Database (NVD) REST API v2
 * at {@code https://services.nvd.nist.gov/rest/json/cves/2.0} to fetch
 * real CVE records for a given CPE 2.3 string.</p>
 *
 * <p>Uses Java 21 {@code HttpClient} with virtual-thread-friendly async
 * {@code .sendAsync()} calls. An optional NVD API key can be set via
 * {@code netsentinel.nvd.api-key} to increase rate limits from 5 to 50 req/30s.</p>
 */
@Component
public class NvdApiClient {

    private static final Logger log = LoggerFactory.getLogger(NvdApiClient.class);

    @Value("${netsentinel.nvd.base-url:https://services.nvd.nist.gov/rest/json/cves/2.0}")
    private String baseUrl;

    @Value("${netsentinel.nvd.api-key:}")
    private String apiKey;

    @Value("${netsentinel.nvd.timeout-seconds:3}")
    private int timeoutSeconds;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public NvdApiClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .version(HttpClient.Version.HTTP_2)
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Asynchronously fetches CVE records from the NVD API for the given CPE string.
     *
     * @param cpeString A CPE 2.3 formatted string, e.g.,
     *                  {@code cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*}
     * @return A CompletableFuture resolving to a list of matched CveRecords,
     *         or an empty list on error/timeout/no results
     */
    public CompletableFuture<List<CveRecord>> fetchByCpe(String cpeString) {
        String encodedCpe = URLEncoder.encode(cpeString, StandardCharsets.UTF_8);
        String url = baseUrl + "?cpeName=" + encodedCpe + "&resultsPerPage=5";

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Accept", "application/json")
                .GET();

        if (apiKey != null && !apiKey.isBlank()) {
            requestBuilder.header("apiKey", apiKey);
        }

        HttpRequest request = requestBuilder.build();
        log.debug("  → NVD API: cpeName={}", cpeString);

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .orTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        List<CveRecord> results = parseNvdResponse(response.body(), cpeString);
                        log.debug("  ← NVD API: {} CVEs for {}", results.size(), cpeString);
                        return results;
                    } else {
                        log.warn("  NVD API HTTP {} for {}", response.statusCode(), cpeString);
                        return List.<CveRecord>of();
                    }
                })
                .exceptionally(ex -> {
                    log.debug("  NVD API unavailable for {} — {}", cpeString, ex.getMessage());
                    return List.of();
                });
    }

    /**
     * Parses the NVD API v2 JSON response body into CveRecord instances.
     */
    public List<CveRecord> parseNvdResponse(String json, String sourceCpe) {
        List<CveRecord> results = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            if (!vulnerabilities.isArray()) return results;

            for (JsonNode vulnNode : vulnerabilities) {
                JsonNode cveNode = vulnNode.path("cve");
                if (cveNode.isMissingNode()) continue;
                try {
                    CveRecord record = parseSingleCve(cveNode, sourceCpe);
                    if (record != null) results.add(record);
                } catch (Exception e) {
                    log.debug("  Could not parse CVE entry: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("  Failed to parse NVD response: {}", e.getMessage());
        }
        return results;
    }

    private CveRecord parseSingleCve(JsonNode cveNode, String sourceCpe) {
        String cveId = cveNode.path("id").asText("UNKNOWN");

        // Extract English description
        String description = "No description available.";
        for (JsonNode desc : cveNode.path("descriptions")) {
            if ("en".equals(desc.path("lang").asText())) {
                description = desc.path("value").asText(description);
                break;
            }
        }

        // Try CVSS v3.1 metrics first, then v3.0
        JsonNode cvssData = null;
        for (String metricKey : List.of("cvssMetricV31", "cvssMetricV30")) {
            JsonNode metricArray = cveNode.path("metrics").path(metricKey);
            if (metricArray.isArray() && metricArray.size() > 0) {
                JsonNode chosen = metricArray.get(0);
                for (JsonNode m : metricArray) {
                    if ("Primary".equals(m.path("type").asText())) { chosen = m; break; }
                }
                cvssData = chosen.path("cvssData");
                break;
            }
        }

        double baseScore = 4.0;
        AttackVector attackVector = AttackVector.NETWORK;
        AttackComplexity attackComplexity = AttackComplexity.LOW;
        PrivilegesRequired privilegesRequired = PrivilegesRequired.NONE;
        UserInteraction userInteraction = UserInteraction.NONE;
        String scope = "UNCHANGED", confImpact = "LOW", integImpact = "LOW", availImpact = "LOW";

        if (cvssData != null && !cvssData.isMissingNode()) {
            baseScore = cvssData.path("baseScore").asDouble(4.0);
            attackVector = parseAttackVector(cvssData.path("attackVector").asText("NETWORK"));
            attackComplexity = "LOW".equals(cvssData.path("attackComplexity").asText("LOW"))
                    ? AttackComplexity.LOW : AttackComplexity.HIGH;
            privilegesRequired = parsePrivilegesRequired(cvssData.path("privilegesRequired").asText("NONE"));
            userInteraction = "NONE".equals(cvssData.path("userInteraction").asText("NONE"))
                    ? UserInteraction.NONE : UserInteraction.REQUIRED;
            scope = cvssData.path("scope").asText(scope);
            confImpact = cvssData.path("confidentialityImpact").asText(confImpact);
            integImpact = cvssData.path("integrityImpact").asText(integImpact);
            availImpact = cvssData.path("availabilityImpact").asText(availImpact);
        }

        // Extract CWE: first "CWE-*" value across all weakness entries (same rule as
        // scripts/build_dataset.py, so inference features match training features)
        String cweId = "NVD-CWE-noinfo";
        cwe:
        for (JsonNode weakness : cveNode.path("weaknesses")) {
            for (JsonNode desc : weakness.path("description")) {
                String v = desc.path("value").asText("");
                if (v.startsWith("CWE-")) {
                    cweId = v;
                    break cwe;
                }
            }
        }

        // CISA KEV: if cisaExploitAdd is present, the CVE is actively exploited in the wild
        boolean exploitInWild = !cveNode.path("cisaExploitAdd").asText("").isBlank();
        boolean patchAvailable = !"Awaiting Analysis".equals(cveNode.path("vulnStatus").asText(""));

        // Affected CPEs: prefer NVD configuration data (version ranges encoded by CpeMatcher);
        // fall back to the CPE we queried with.
        List<String> affected = CpeMatcher.extractAffected(cveNode);
        if (affected.isEmpty() && sourceCpe != null) affected = List.of(sourceCpe);

        String published = cveNode.path("published").asText("");
        int year = published.length() >= 4 ? Integer.parseInt(published.substring(0, 4))
                : CveRecord.yearFromId(cveId);

        return new CveRecord(
                cveId, description, baseScore,
                attackVector, attackComplexity, privilegesRequired, userInteraction,
                cweId, affected, patchAvailable, exploitInWild,
                year, CveRecord.vendorFromCpes(affected),
                scope, confImpact, integImpact, availImpact
        );
    }

    private AttackVector parseAttackVector(String s) {
        return switch (s.toUpperCase()) {
            case "ADJACENT_NETWORK", "ADJACENT" -> AttackVector.ADJACENT;
            case "LOCAL"    -> AttackVector.LOCAL;
            case "PHYSICAL" -> AttackVector.PHYSICAL;
            default         -> AttackVector.NETWORK;
        };
    }

    private PrivilegesRequired parsePrivilegesRequired(String s) {
        return switch (s.toUpperCase()) {
            case "LOW"  -> PrivilegesRequired.LOW;
            case "HIGH" -> PrivilegesRequired.HIGH;
            default     -> PrivilegesRequired.NONE;
        };
    }
}

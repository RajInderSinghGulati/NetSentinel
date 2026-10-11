package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Tier 2: Hybrid CVE Database with NVD API primary + simulated fallback.
 *
 * <p>Lookup strategy:
 * <ol>
 *   <li>If {@code netsentinel.nvd.enabled=true}: query the NVD REST API v2
 *       asynchronously with a configurable timeout.</li>
 *   <li>If the NVD call returns results: cache and return them.</li>
 *   <li>If the NVD API is unreachable, times out, or returns no results:
 *       fall back silently to the {@link SimulatedCveDatabase}.</li>
 * </ol>
 * </p>
 *
 * <p>Results are cached in-memory per CPE string to avoid repeated API
 * calls within the same JVM session (one-shot scan tool pattern).</p>
 */
@Primary
@Component
public class HybridCveDatabase implements CveDatabase {

    private static final Logger log = LoggerFactory.getLogger(HybridCveDatabase.class);

    @Value("${netsentinel.nvd.enabled:true}")
    private boolean nvdEnabled;

    @Value("${netsentinel.nvd.timeout-seconds:3}")
    private int timeoutSeconds;

    private final NvdApiClient nvdApiClient;
    private final SimulatedCveDatabase simulatedDb;

    /** In-memory cache: CPE string → resolved CVE list */
    private final ConcurrentHashMap<String, List<CveRecord>> cache = new ConcurrentHashMap<>();

    /** Track whether we've had at least one successful NVD API hit this session */
    private volatile boolean nvdAvailable = true;
    private volatile int nvdHits = 0;
    private volatile int nvdMisses = 0;

    public HybridCveDatabase(NvdApiClient nvdApiClient,
                              @Qualifier("simulatedCveDb") SimulatedCveDatabase simulatedDb) {
        this.nvdApiClient = nvdApiClient;
        this.simulatedDb = simulatedDb;
    }

    @Override
    public List<CveRecord> findByCpe(String cpeString) {
        // Check in-memory cache first
        if (cache.containsKey(cpeString)) {
            return cache.get(cpeString);
        }

        List<CveRecord> results = List.of();

        // Attempt NVD API lookup if enabled and still considered available
        if (nvdEnabled && nvdAvailable) {
            try {
                results = nvdApiClient.fetchByCpe(cpeString)
                        .get(timeoutSeconds, TimeUnit.SECONDS);

                if (!results.isEmpty()) {
                    nvdHits++;
                    log.debug("  [NVD] {} CVEs from API for {}", results.size(), cpeString);
                    cache.put(cpeString, results);
                    return results;
                }
                // NVD returned empty — still try simulated fallback
            } catch (TimeoutException e) {
                nvdMisses++;
                log.warn("  [NVD] Timeout for {} — falling back to simulated DB", cpeString);
                if (nvdMisses >= 3) {
                    nvdAvailable = false;
                    log.warn("  [NVD] 3+ timeouts — disabling NVD API for this session");
                }
            } catch (InterruptedException | ExecutionException e) {
                nvdMisses++;
                log.debug("  [NVD] Error for {}: {}", cpeString, e.getMessage());
            }
        }

        // Fallback: simulated database
        results = simulatedDb.findByCpe(cpeString);
        if (!results.isEmpty()) {
            log.debug("  [Simulated] {} CVEs from local DB for {}", results.size(), cpeString);
        }

        cache.put(cpeString, results);
        return results;
    }

    @Override
    public List<CveRecord> findAll() {
        return simulatedDb.findAll();
    }

    /**
     * Returns a summary of NVD API usage for logging/diagnostic purposes.
     */
    public String getSessionStats() {
        return "NVD API session stats: %d hits, %d misses, available=%s, cache=%d entries"
                .formatted(nvdHits, nvdMisses, nvdAvailable, cache.size());
    }
}

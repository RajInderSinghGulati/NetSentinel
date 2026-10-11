package com.netsentinel.cve;

import com.netsentinel.model.CveRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reproducible CVE source backed by a pinned NVD snapshot file (NVD API 2.0 JSON,
 * as produced by {@code scripts/fetch_nvd_snapshot.py}).
 *
 * <p>The snapshot is read from {@code netsentinel.nvd.snapshot-path} (filesystem) or,
 * if unset/missing, the classpath resource {@code nvd/snapshot.json}. When neither
 * exists the database is simply empty.</p>
 */
@Component("offlineNvdDb")
public class OfflineNvdCveDatabase implements CveDatabase {

    private static final Logger log = LoggerFactory.getLogger(OfflineNvdCveDatabase.class);
    private static final String CLASSPATH_SNAPSHOT = "/nvd/snapshot.json";

    private final List<CveRecord> records = new ArrayList<>();
    private final ConcurrentHashMap<String, List<CveRecord>> cache = new ConcurrentHashMap<>();

    public OfflineNvdCveDatabase(NvdApiClient parser,
                                 @Value("${netsentinel.nvd.snapshot-path:}") String snapshotPath) {
        String json = load(snapshotPath);
        if (json == null) {
            log.info("  No offline NVD snapshot found — offline DB empty");
            return;
        }
        records.addAll(parser.parseNvdResponse(json, null));
        log.info("✓ Loaded {} CVE records from offline NVD snapshot", records.size());
    }

    private String load(String snapshotPath) {
        try {
            if (snapshotPath != null && !snapshotPath.isBlank()) {
                Path p = Path.of(snapshotPath);
                if (Files.exists(p)) return Files.readString(p, StandardCharsets.UTF_8);
            }
            try (InputStream in = getClass().getResourceAsStream(CLASSPATH_SNAPSHOT)) {
                if (in != null) return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            log.warn("  Could not read NVD snapshot: {}", e.getMessage());
        }
        return null;
    }

    public boolean isEmpty() {
        return records.isEmpty();
    }

    @Override
    public List<CveRecord> findByCpe(String cpeString) {
        return cache.computeIfAbsent(cpeString, q -> {
            // A CVE can affect many vendors (e.g. Log4Shell); report the matched host's vendor.
            String vendor = CveRecord.vendorFromCpes(List.of(q));
            return records.stream()
                    .filter(cve -> cve.affectedCpes().stream().anyMatch(a -> CpeMatcher.matches(q, a)))
                    .map(cve -> cve.withVendor(vendor))
                    .toList();
        });
    }

    @Override
    public List<CveRecord> findAll() {
        return List.copyOf(records);
    }
}

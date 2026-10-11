package com.netsentinel.scanner;

import com.netsentinel.model.HostFingerprint.NetworkTier;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Declared assets for live scans. A scan can observe open ports and banners but not an asset's role,
 * so tier and criticality come from this file (the "zone model" assumption stated in the paper).
 *
 * <pre>
 * hosts:
 *   - name: web-dmz
 *     address: 127.0.0.1
 *     ports: [18080]
 *     tier: DMZ            # DMZ | APPLICATION | DATA | CROWN_JEWEL
 *     criticality: 5       # 1-10
 *     os: Alpine Linux
 * </pre>
 */
public final class LiveInventory {

    public record Entry(String name, String address, List<Integer> ports, NetworkTier tier,
                        int criticality, String os) {}

    private LiveInventory() {}

    public static List<Entry> load(Path file) throws IOException {
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return parse(new Yaml().load(r));
        }
    }

    @SuppressWarnings("unchecked")
    static List<Entry> parse(Object doc) {
        if (!(doc instanceof Map<?, ?> root) || !(root.get("hosts") instanceof List<?> hosts)) {
            throw new IllegalArgumentException("inventory must contain a 'hosts' list");
        }
        List<Entry> out = new ArrayList<>();
        for (Object o : hosts) {
            Map<String, Object> h = (Map<String, Object>) o;
            String name = String.valueOf(h.get("name"));
            String address = String.valueOf(h.get("address"));
            List<Integer> ports = new ArrayList<>();
            for (Object p : (List<?>) h.getOrDefault("ports", List.of())) ports.add(((Number) p).intValue());
            if (name.equals("null") || address.equals("null") || ports.isEmpty()) {
                throw new IllegalArgumentException("host needs name, address and ports: " + h);
            }
            NetworkTier tier = NetworkTier.valueOf(String.valueOf(h.getOrDefault("tier", "APPLICATION")).toUpperCase());
            int crit = ((Number) h.getOrDefault("criticality", 5)).intValue();
            out.add(new Entry(name, address, ports, tier, crit, String.valueOf(h.getOrDefault("os", "unknown"))));
        }
        return out;
    }
}

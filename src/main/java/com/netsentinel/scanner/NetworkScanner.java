package com.netsentinel.scanner;

import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.ScanTarget;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Pluggable network scanner interface for Tier 1: Ingestion & Discovery.
 *
 * <p>Implementations scan a target CIDR range and produce strongly-typed
 * {@link HostFingerprint} records. The interface supports async execution
 * and progress callbacks for real-time UI updates.</p>
 */
public interface NetworkScanner {

    /**
     * Asynchronously scans the target subnet and returns discovered host fingerprints.
     *
     * @param target           The scan target (CIDR range + configuration)
     * @param progressCallback Called each time a new host is discovered
     * @return Future containing the complete list of discovered hosts
     */
    CompletableFuture<List<HostFingerprint>> scan(ScanTarget target, Consumer<HostFingerprint> progressCallback);
}

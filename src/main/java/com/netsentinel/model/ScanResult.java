package com.netsentinel.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Aggregate result of a complete NetSentinel scan pipeline execution.
 * Contains all outputs from the four-tier pipeline.
 */
public class ScanResult {

    public enum Status { PENDING, SCANNING, ENRICHING, GRAPHING, ANALYZING, COMPLETE, FAILED }

    private final String scanId;
    private final ScanTarget target;
    private final Instant startTime;
    private Instant endTime;
    private Status status;
    private String statusMessage;

    // Tier 1 outputs
    private List<HostFingerprint> discoveredHosts;

    // Tier 2 outputs
    private int totalCvesMatched;
    private int graphNodeCount;
    private int graphEdgeCount;

    // Tier 3 outputs
    private List<AttackPath> attackPaths;
    private double highestPathRisk;

    // Tier 4 outputs
    private String remediationPlaybook;
    private Map<String, Object> graphData;

    public ScanResult(ScanTarget target) {
        this.scanId = UUID.randomUUID().toString().substring(0, 8);
        this.target = target;
        this.startTime = Instant.now();
        this.status = Status.PENDING;
        this.statusMessage = "Initializing scan...";
    }

    // --- Getters and Setters ---

    public String getScanId() { return scanId; }
    public ScanTarget getTarget() { return target; }
    public Instant getStartTime() { return startTime; }
    public Instant getEndTime() { return endTime; }
    public void setEndTime(Instant endTime) { this.endTime = endTime; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getStatusMessage() { return statusMessage; }
    public void setStatusMessage(String statusMessage) { this.statusMessage = statusMessage; }

    public List<HostFingerprint> getDiscoveredHosts() { return discoveredHosts; }
    public void setDiscoveredHosts(List<HostFingerprint> discoveredHosts) { this.discoveredHosts = discoveredHosts; }

    public int getTotalCvesMatched() { return totalCvesMatched; }
    public void setTotalCvesMatched(int totalCvesMatched) { this.totalCvesMatched = totalCvesMatched; }
    public int getGraphNodeCount() { return graphNodeCount; }
    public void setGraphNodeCount(int graphNodeCount) { this.graphNodeCount = graphNodeCount; }
    public int getGraphEdgeCount() { return graphEdgeCount; }
    public void setGraphEdgeCount(int graphEdgeCount) { this.graphEdgeCount = graphEdgeCount; }

    public List<AttackPath> getAttackPaths() { return attackPaths; }
    public void setAttackPaths(List<AttackPath> attackPaths) {
        this.attackPaths = attackPaths;
        this.highestPathRisk = attackPaths.stream()
                .mapToDouble(AttackPath::cumulativeRisk)
                .max().orElse(0.0);
    }
    public double getHighestPathRisk() { return highestPathRisk; }

    public String getRemediationPlaybook() { return remediationPlaybook; }
    public void setRemediationPlaybook(String remediationPlaybook) { this.remediationPlaybook = remediationPlaybook; }
    public Map<String, Object> getGraphData() { return graphData; }
    public void setGraphData(Map<String, Object> graphData) { this.graphData = graphData; }

    public long durationMs() {
        Instant end = endTime != null ? endTime : Instant.now();
        return end.toEpochMilli() - startTime.toEpochMilli();
    }
}

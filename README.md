# NetSentinel-AI 🛡️⚡

**Java-Native Autonomous Network Vulnerability Assessment, Attack Graph Modeler & Multi-Hop Path Prediction Engine**

[![Java](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![JGraphT](https://img.shields.io/badge/JGraphT-1.5.3-blue.svg)](https://jgrapht.org/)
[![DL4J](https://img.shields.io/badge/Deeplearning4j-1.0.0--M2.1-red.svg)](https://deeplearning4j.konduit.ai/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## 📌 Overview

NetSentinel-AI is a proactive vulnerability assessment and automated remediation platform written natively in modern Java. Rather than functioning as a reactive Network Intrusion Detection System (NIDS) processing live attack traffic, NetSentinel-AI proactively scans network subnets, parses service banners, maps software configurations to known Common Vulnerabilities and Exposures (CVEs), builds a topological attack graph, predicts multi-hop compromise chains using in-JVM machine learning, and synthesizes automated remediation playbooks (Ansible & Bash).

---

## 🏗️ Four-Tier Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          NetSentinel-AI Pipeline                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────┐           ┌───────────────────────────────┐  │
│  │   Cytoscape.js Web UI     │◄─────────►│    Spring Boot 3 REST API     │  │
│  │  (Interactive Topology)   │           │      & WebSocket/STOMP        │  │
│  └─────────────┬─────────────┘           └───────────────┬───────────────┘  │
│                │                                         │                  │
│  ══════════════╪═════════════════════════════════════════╪═════════════════ │
│                ▼                                         ▼                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │               ScanOrchestrator (Pipeline Coordinator)                 │  │
│  └──────┬──────────────────┬───────────────────┬──────────────────┬──────┘  │
│         │                  │                   │                  │         │
│  ═══════╪══════════════════╪═══════════════════╪══════════════════╪════════ │
│         ▼                  ▼                   ▼                  ▼         │
│   [ Tier 1: DISCOVERY ]  [ Tier 2: GRAPH ]   [ Tier 3: AI/ML ]  [ Tier 4 ]  │
│  ┌────────────────────┐ ┌────────────────┐ ┌─────────────────┐ ┌──────────┐ │
│  │ Virtual Threads    │ │ JGraphT        │ │ DL4J MLP Neural │ │ Ansible  │ │
│  │ Network Scanner    │ │ Directed       │ │ Network Scorer  │ │ Playbook │ │
│  │ - Banner Grabbing  │ │ Multigraph     │ ├─────────────────┤ │ Generator│ │
│  │ - CPE 2.3 Tagging  │ │ - Node: Host   │ │ Yen's K-Shortest│ └──────────┘ │
│  │ - Port Probing     │ │ - Edge: Exploit│ │ Paths Algorithm │              │
│  └────────────────────┘ └────────────────┘ └─────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Tier 1: Ingestion & Discovery Engine**
   - Spawns lightweight **Virtual Threads** (`Executors.newVirtualThreadPerTaskExecutor()`) to probe subnets concurrently.
   - Converts raw probe responses into strongly typed Java `record` instances (`HostFingerprint`) containing IP, ports, banners, and CPE strings.

2. **Tier 2: CVE Ingestion & Graph Modeler**
   - Matches discovered software CPEs against CVEs enriched with CVSS v3.1 vector breakdown.
   - Employs **JGraphT** to construct a `DirectedWeightedMultigraph<HostNode, ExploitEdge>` mapping firewall boundaries (DMZ $\to$ App $\to$ Data $\to$ Crown Jewels).

3. **Tier 3: AI Reasoning Core**
   - **Lateral Compromise Scorer (Deeplearning4j):** In-JVM Multi-Layer Perceptron (MLP) calculating edge exploitability probabilities $P(\text{Compromise})$.
   - **Multi-Hop Path Extraction:** Runs **Yen's $K$-Shortest Paths** algorithm to isolate the top-$K$ critical compromise vectors from external/DMZ entry nodes to crown jewel servers.

4. **Tier 4: Presentation & Closed-Loop Remediation**
   - **Control Plane REST API & WebSocket/STOMP:** Real-time event broadcasting and pipeline telemetry.
   - **Interactive Cytoscape.js Dashboard:** Visual directed attack graph with real-time node drill-down and attack path tracing.
   - **Automated Playbook Synthesis:** Generates idempotent Ansible playbooks and emergency hardening scripts targeting bottleneck CVEs.

---

## 🚀 Quickstart

### Prerequisites
- **JDK 21 LTS** or higher
- **Maven 3.8+**

### Build & Run
```bash
# Clone the repository
git clone git@github.com:RajInderSinghGulati/NetSentinel.git
cd NetSentinel

# Compile & Package
mvn clean package -DskipTests

# Run the Application
mvn spring-boot:run
```

### Access Dashboard & APIs
- **Web Dashboard:** Open [http://localhost:8080](http://localhost:8080)
- **Synchronous Scan API:**
```bash
curl -X POST http://localhost:8080/api/scan/sync \
     -H "Content-Type: application/json" \
     -d '{"cidr":"192.168.10.0/24"}'
```
- **Fetch Attack Paths:**
```bash
curl http://localhost:8080/api/scan/{scanId}/paths
```
- **Fetch Remediation Playbook:**
```bash
curl http://localhost:8080/api/scan/{scanId}/remediation
```

---

## 📊 Tech Stack

| Layer | Framework / Library | Role |
| :--- | :--- | :--- |
| **Core Platform** | Java 21 LTS (OpenJDK) | Virtual threads (Loom), sealed classes, record types |
| **Backend & API** | Spring Boot 3.2.5, Spring WebSocket | REST endpoints, STOMP event broker, service lifecycle |
| **Graph Analysis** | JGraphT 1.5.3 | Topological attack graph modeling, Yen's $K$-Shortest Paths |
| **Machine Learning**| Deeplearning4j (DL4J) + ND4J 1.0.0-M2.1 | In-JVM neural network for compromise probability estimation |
| **Frontend UI** | Cytoscape.js, Dagre, Vanilla JS/CSS | Interactive attack graph visualization and path highlights |
| **Automation** | Ansible YAML & POSIX Shell templates | Idempotent closed-loop vulnerability remediation playbooks |

---

## 📄 License
This project is licensed under the Apache License 2.0.

# M.A.N.T.I.S: Master Project Reference Document

**Project Name:** MANTIS (Minimalist Alert Network for Threat Intelligence System)
**Goal:** Build a Host-Based Intrusion Detection System (HIDS) from scratch using Python.
**Target OS:** Linux (Kali, Ubuntu, RedHat)
**Deployment:** Enterprise SIEM architecture (Sensors reporting to a Central Dashboard)

This document serves as the absolute source of truth for the MANTIS project. Use this document as context for generating grading rubrics, project proposals, methodology records, dissertation chapters, or when asking AI assistants for technical help.

---

## 1. Core Architecture and Constraints (STRICT)

The most defining feature of MANTIS is its **Zero-Dependency Policy**. The core detection engines are built exclusively using the **Python Standard Library** (`socket`, `struct`, `math`, `collections`).

*   **No Scikit-Learn (sklearn)**
*   **No Pandas / NumPy**
*   **No Scapy / Pcapy**
*   **No TensorFlow / PyTorch**

**Why? (Educational Focus):** To prove a "First Principles" understanding of mathematics, networking protocols, and machine learning algorithms. The developer wrote the Z-Score, K-Nearest Neighbors (KNN), Naive Bayes, K-Means clustering, and Protocol Parsing algorithms entirely from scratch.

---

## 2. Directory Structure (Separation of Concerns)

The project is structured into two main components: Code (`src/`) and Documentation (`docs/`).

```text
mantis/
├── docs/                        # Project Proposals, Meeting Minutes, Dissertations
│   ├── MANTIS_MASTER_REFERENCE.md      # (This document)
│   ├── DISSERTATION_METHODOLOGY.md     # Agile Kanban methodology documentation
│   ├── MANTIS_PROJECT_PROPOSAL.md      # Final submitted proposal markdown
│   ├── MANTIS_SE_PROJECT_*-FINAL.docx  # Final formatted Word documents for grading
│   └── ...                             
├── src/                         # Executable Python Code
│   ├── main.py                  # Entry Point (starts Sensor + Web Dashboard threads)
│   ├── install.sh               # Linux autonomous deployment script
│   ├── dashboard_ui/            # Web Frontend (Instana/Motadata style UI)
│   │   ├── siem.py              # Web server handling API routing and templates
│   │   └── web_template.html    # The HTML/CSS/JS for the Multi-Tab Dashboard
│   ├── engines/                 # The 5 Detection Algorithms (First Principles)
│   │   ├── z_score.py           # Engine 1: DDoS Detection
│   │   ├── knn.py               # Engine 2: Port Scan Detection
│   │   ├── naive_bayes.py       # Engine 3: Payload Inspection (SQLi/XSS)
│   │   ├── bloom.py             # Engine 4: IP Reputation Blacklist
│   │   └── kmeans.py            # Engine 5: Unsupervised Traffic Clustering
│   ├── sensor_node/             # The Raw Socket packet sniffer
│   │   └── sensor.py            # Parses OSI Layer 2-7 and feeds the distinct Engines
│   └── utils/                   
│       ├── active_defense.py    # Interfaces with 'iptables' to block attackers
│       └── logger.py            # Handles remote Syslog over UDP 9999
├── README.md                    # Quickstart guide
└── INSTALL.md                   # Installation instructions
```

---

## 3. The 5 Strict Implementation Phases

MANTIS was developed iteratively across 5 distinct phases to ensure mathematical understanding before scaling the complexity:

### Phase 1: The Sensor (Packet Capture)
*   **Technology:** Python `socket` library using `AF_PACKET` and `SOCK_RAW` on `eth0`.
*   **Mechanism:** Promiscuous mode capture at Data Link Layer (OSI Layer 2). Uses the `struct` module to manually unpack bitwise headers for Ethernet MACs, IPv4 headers, and TCP/UDP ports.

### Phase 2: Statistical Engine (L3/L4 Flood Detection)
*   **Technology:** Z-Score Anomaly Detection.
*   **Threat Vector:** Volumetric DDoS / SYN Floods.
*   **Mechanism:** Analyzes network flow density (Packets Per Second). Calculates a running Mean and Standard Deviation. If the current traffic spikes by a Z-score greater than 3.0 (representing 99.7% beyond normal variance), an alert is triggered.

### Phase 3: Behavioral Engine (L4 Reconnaissance Detection)
*   **Technology:** K-Nearest Neighbors (KNN) & K-Means Clustering.
*   **Threat Vector:** Nmap Horizontal/Vertical Port Scans.
*   **Mechanism:** 
    *   **KNN:** Counts the number of *unique destination ports* accessed by a single IP per second. Classifies behavior in a multi-dimensional grid against known "Scan" patterns.
    *   **K-Means:** An unsupervised learning algorithm that clusters traffic based on standard flows vs. rapid, scattered port access.

### Phase 4: Payload Engine (L7 DPI - Deep Packet Inspection)
*   **Technology:** Naive Bayes text classification.
*   **Threat Vector:** SQL Injection (SQLi) and Cross-Site Scripting (XSS).
*   **Mechanism:** Inspects the raw byte payload of TCP port 80/443 traffic. It strips the text and applies a custom-built Bayesian probability mathematical model to score strings matching malicious keywords (e.g., `' OR 1=1`, `<script>`).

### Phase 5: IP Reputation & Enterprise SIEM (Dashboard)
*   **Technology:** Bloom Filters & `http.server`.
*   **Threat Vector:** Known Malicious Actors & Autonomous Mitigation.
*   **Mechanism:**
    *   **Bloom Filter:** An ultra-fast, memory-efficient probabilistic data structure that checks incoming source IPs against a massive blacklist in `O(k)` time complexity.
    *   **Active Defense:** Interfaces directly with Linux `iptables` to block IP addresses autonomously when high-confidence attacks are detected.
    *   **SIEM Dashboard:** `siem.py` runs a multi-tab web application (Instana styling) highlighting infrastructure loads, threat detection telemetry, a real-time Wireshark packet view, and architecture documentation.

---

## 4. How to Explain MANTIS to Evaluate the Code (Viva / Defense preparation)

If an academic supervisor asks: *"Why didn't you just use Scikit-Learn for K-Means?"*

**Answer:**
*"The goal of the MANTIS project was not just operational deployment, but demonstrating a fundamental computer science understanding of the underlying mathematics. By writing algorithms like K-Means and Naive Bayes from scratch using only the Python standard library, I avoided massive dependency overheads and proved I understand how Euclidean distance and Bayesian probability equations actually identify network anomalies bit-by-bit."*

If they ask: *"How do you capture traffic without Pcap?"*

**Answer:**
*"By interacting directly with the Linux kernel using `socket.AF_PACKET`. I bypass the OS layer and read the raw 1s and 0s coming off the Network Interface Card (NIC), manually unpacking the Byte strings using the `struct` library to separate the MAC address from the IP protocol headers."*

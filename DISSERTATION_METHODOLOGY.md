# MANTIS: INTELLIGENT ALERT MANAGEMENT SYSTEM WITH AUTOMATED THREAT DETECTION
## Comprehensive Dissertation Methodology & Implementation Guide

### 1. RESEARCH METHODOLOGY
**Primary Approach:** Constructive Research Methodology
**Phases:**
1.  **Problem Identification:** Current Intrusion Detection Systems (IDS) rely on heavy "Black Box" machine learning libraries (e.g., Scikit-Learn, TensorFlow), causing severe resource bloat (CPU/RAM) and a lack of auditability.
2.  **Objectives Definition:** Build a "Zero-Dependency," transparent Host-Based IDS (HIDS) utilizing only the Python Standard Library.
3.  **Design and Development:** Engineer **four** mathematical detection engines (Statistical, Behavioral, Probabilistic, Reputation) from scratch.
4.  **Demonstration:** Test the artifact in a virtualized lab using Kali Linux and the CIC-IoT2023 dataset.
5.  **Evaluation:** Measure detection accuracy (TPR/FPR) and benchmark CPU/RAM efficiency against standard heavy libraries.
6.  **Communication:** Compile findings into the final dissertation.
**Justification:** Constructive research is the gold standard for software engineering, as it validates theories through the actual construction and benchmarking of an IT artifact.

### 2. SOFTWARE DEVELOPMENT METHODOLOGY
**Primary Model:** Agile Kanban (Optimized for Solo Project)
**Why Kanban:**
-   **Visual Workflow:** Allows clear tracking of separate modules (Sensor, Math Engines, Dashboard).
-   **Flexibility:** No fixed sprint overhead, allowing pacing adjustments around academic deadlines.
-   **Continuous Delivery:** Perfect for integrating one mathematical algorithm at a time.

**Kanban Board Structure:**
-   **Backlog:** E.g., "Research Bloom Filter math."
-   **To Do (Weekly):** E.g., "Implement Raw Sockets."
-   **In Progress (WIP Limit = 2):** E.g., "Coding KNN algorithm."
-   **Testing (WIP Limit = 1):** E.g., "Running Nmap scan against KNN."
-   **Done:** E.g., "Sensor module completed."

### 3. DETECTION ENGINE METHODOLOGY (ZERO-DEPENDENCY)
Instead of relying on CRISP-DM (which is for standard data mining), MANTIS uses a **First-Principles Engineering Pipeline**:
1.  **Packet Capture (Data-Link Layer):** Direct kernel interaction using Python `socket.SOCK_RAW`.
2.  **Binary Unpacking:** Using `struct.unpack()` to manually slice Ethernet and IP headers.
3.  **Algorithmic Routing:**
    -   **IP Data** routed to Reputation Engine (Bloom Filter).
    -   **Volume Data** routed to Statistical Engine (Z-Score).
    -   **Port/Connection Data** routed to Behavioral Engine (KNN).
    -   **Payload Data** routed to Probabilistic Engine (Naive Bayes).
4.  **Alert Generation:** Outputting anomalies to the CLI Dashboard and UDP/CSV logs.

### 4. DATA COLLECTION & VALIDATION STRATEGY
**Benign Data Collection:**
-   **Environment:** Ubuntu Linux Server (Victim VM).
-   **Traffic:** Normal background processes, apt updates, standard HTTP requests.

**Malicious Data Collection (Validation):**
-   **Live Simulation:** Using Kali Linux (Attacker VM) to launch Nmap (Port Scans), Hping3 (SYN Floods), and SQLmap (Web Attacks).
-   **Dataset Replay:** Utilizing the **CIC-IoT2023 Dataset**.
    -   **Why:** Contains 33 modern attack types specifically targeting Linux/IoT environments.
    -   **Method:** Replaying PCAP files through the MANTIS sensor to benchmark accuracy against a global standard.

### 5. FEATURE ENGINEERING (PACKET EXTRACTION)
Because MANTIS uses zero external dependencies (No Scapy), feature extraction is done manually via byte slicing:
-   **Network Features:** Source IP, Destination IP, Protocol (TCP/UDP/ICMP).
-   **Transport Features:** Source Port, Destination Port, TCP Flags (SYN, ACK).
-   **Derived Behavioral Features:**
    -   **Delta-T:** Time between packets from the same IP.
    -   **Port Delta:** Tracking incremental port connection attempts.
-   **Payload Features:** UTF-8 decoded text extracted from the data segment of TCP packets.

### 6. MATHEMATICAL MODELS (THE 4 ENGINES)
MANTIS replaces heavy ML libraries with manually coded mathematical algorithms:

**A. Statistical Engine (Z-Score) $\rightarrow$ DDoS/Flood Detection**
-   **Formula:** $Z = \frac{X - \mu}{\sigma}$
-   **Function:** Measures traffic volume against a rolling historical baseline. Detects sudden spikes (Floods).

**B. Behavioral Engine (K-Nearest Neighbors) $\rightarrow$ Port Scan Detection**
-   **Formula:** Euclidean Distance $d(p, q) = \sqrt{\sum_{i=1}^{n} (p_i - q_i)^2}$
-   **Function:** Plots connection vectors (Unique Ports vs Packet Count). Identifies the "jumping" behavior typical of reconnaissance scans.

**C. Probabilistic Engine (Naive Bayes) $\rightarrow$ Web Attack Detection**
-   **Formula:** $P(Attack | Words) = \frac{P(Words | Attack) \times P(Attack)}{P(Words)}$
-   **Function:** Probabilistic text analysis checking for malicious keywords (e.g., UNION, SELECT).

**D. Reputation Engine (Bloom Filter) $\rightarrow$ Threat Intelligence**
-   **Formula:** Local Hashing $H_k(x)$ mapping to Bit Array $B$.
-   **Function:** Probabilistic Data Structure providing $O(1)$ lookup speed for blocking known malicious IPs (Blacklisting) with minimal memory footprint.

### 7. TESTING METHODOLOGY & TEST CASES
**Testing Framework:** Modified V-Model Approach

**A. Algorithm Test Cases**
-   **Test Case ALG-01:** Send 10,000 packets in 1 second. **Expected:** Z-Score exceeds threshold (>3), triggers DDoS Alert.
-   **Test Case ALG-02:** Connect to ports 21, 22, 23, 24 sequentially. **Expected:** KNN calculates high distance variance, triggers Port Scan Alert.
-   **Test Case ALG-03:** Send TCP packet with "UNION SELECT". **Expected:** Naive Bayes calculates Probability > 0.9, triggers SQLi Alert.
-   **Test Case ALG-04:** Send packet from Blacklisted IP. **Expected:** Bloom Filter returns True, packet dropped immediately.

**B. Database / Logging Test Cases**
-   **Test Case DB-01:** Trigger 50 simultaneous alerts. **Expected:** CSV logger handles concurrent writes via `threading.Lock()` without corruption.

**C. Distributed Architecture Test Cases**
-   **Test Case DIST-01:** Sensor (Fedora) detects attack. **Expected:** Dashboard (Ubuntu) receives UDP alert and displays it in real-time.

**D. UI/UX Related Test Cases**
-   **Test Case UI-01:** Critical alert generated. **Expected:** CLI Dashboard highlights the alert in RED text using ANSI escape codes.

**E. Evaluation Metrics**
-   **Accuracy Target:** > 95% Detection Rate on CIC-IoT2023 dataset.
-   **Performance Target:** CPU usage < 5%, RAM < 50MB (proving the Zero-Dependency advantage).

### 8. SYSTEM ARCHITECTURE
**Layered Architecture:**
-   **Layer 1: Data Link (The Sensor)** Binds to `eth0`/`wlan0`, captures raw hexadecimal data via `AF_PACKET`.
-   **Layer 2: Processing (The Core)** Threads route data to Z-Score, KNN, Bloom Filter, and Naive Bayes engines.
-   **Layer 3: Persistence (The Logger)** Writes alerts to local CSV file.
-   **Layer 4: Network (The Transmitter)** Sends UDP alerts to central dashboard/SIEM.
-   **Layer 5: Presentation (The Dashboard)** Real-time command-line interface visualizing system health and active threats.

### 9. IMPLEMENTATION TIMELINE
-   **Month 1-2:** Literature Review, VirtualBox/Kali Setup, CIC-IoT2023 download.
-   **Month 3:** Phase 1 Code: Implement Raw Sockets and packet unpacking.
-   **Month 4:** Phase 2 Code: Code Z-Score and Naive Bayes algorithms.
-   **Month 5:** Phase 3 Code: Code KNN algorithm and Bloom Filter.
-   **Month 6:** Testing phase against live Kali attacks & Distributed Setup.
-   **Month 7:** Benchmarking CPU/RAM against Scikit-Learn.
-   **Month 8:** Final Dissertation writing and formatting.

### 10. LITERATURE REVIEW STRATEGY
**Focus Areas:** Lightweight Intrusion Detection, Anomaly vs. Signature-based detection, ML bloat in cybersecurity, HIDS vs NIDS architectures.
**Databases:** IEEE Xplore, ACM, Google Scholar.
**Constraint:** Prioritize papers from 2022-2025.

### 11. DISSERTATION STRUCTURE
1.  Introduction
2.  Literature Review
3.  Research Methodology
4.  System Design & Implementation
5.  Experimental Setup & Testing
6.  Results & Analysis
7.  Discussion
8.  Conclusion & Future Work

### 12. TECHNOLOGY STACK
-   **Language:** Python 3.8+
-   **Libraries:** Strictly standard (`socket`, `struct`, `math`, `time`, `threading`, `csv`, `zlib`, `argparse`). NO `pip install` allowed for detection core.
-   **Environment:** VirtualBox, Ubuntu Server (Host), Kali Linux (Attacker).
-   **Dataset:** CIC-IoT2023.

### 13. EXPECTED OUTCOMES
**Outcome:** A functioning, auditable HIDS proving that "First Principles" coding uses drastically fewer resources than commercial ML frameworks while maintaining high accuracy. Now supports Distributed Architecture for Enterprise Scalability.

### 14. RISK MITIGATION
-   **Risk (Python Speed):** Python is an interpreted language and can drop packets under high load.
-   **Mitigation:** Implementation of the `threading` module to decouple packet sniffing (fast) from algorithmic analysis (slower), and use of `Bloom Filter` for O(1) early dropping.

### 15. EVALUATION CRITERIA
Successfully detect SYN Floods, Port Scans, and SQL Injections.
Prove statistically that MANTIS consumes less CPU/RAM than a comparable script written using `scikit-learn` and `scapy`.

### 16. METHODOLOGY SUMMARY
-   **Framework:** Constructive Research.
-   **Development:** Agile Kanban.
-   **Engineering:** Zero-Dependency, Raw Socket, Math-driven pipeline.
-   **Validation:** V-Model testing via Kali Linux & CIC-IoT2023.

### 17. SUPERVISOR MEETING SCHEDULE
Monthly reviews covering: Architecture approval, Algorithm validation, Testing results, and Draft chapter reviews.

### 18. PROGRESS TILL DATE (Example)
-   Completed comprehensive literature review.
-   Finalized 4 mathematical models (Z-Score, KNN, Naive Bayes, Bloom Filter).
-   Implemented Distributed Logging Architecture (UDP).
-   Fully functional CLI tool (`mantis.py`).

### 19. CONCLUSION
MANTIS addresses the critical issues of resource bloat and opacity in modern cybersecurity tools. By engineering a Host-Based Intrusion Detection System entirely from "First Principles" using the Python Standard Library, this project demonstrates that effective threat detection does not require massive, opaque machine learning frameworks. The implementation of custom Z-Score, K-Nearest Neighbors, Naive Bayes, and Bloom Filter algorithms successfully detects volumetric floods, reconnaissance scans, payload injections, and known malicious actors.
Through rigorous testing using Kali Linux and the CIC-IoT2023 dataset, MANTIS proves that transparency and performance can coexist. The resulting artifact is a lightweight, fully auditable security agent that provides high detection accuracy while consuming significantly fewer CPU and RAM resources, making it an ideal solution for low-power edge servers and IoT environments.

### 19.1 Future Enhancement / Future Scope
-   **Active Prevention (IPS):** Upgrading the system from purely detection (IDS) to an Intrusion Prevention System by integrating with Linux `iptables` to automatically drop malicious IPs.
-   **Encrypted Payload Analysis:** Implementing advanced flow-metadata analysis to infer malicious behavior inside HTTPS traffic without decryption.
-   **Cloud Deployment:** Adapting the MANTIS architecture to monitor Kubernetes clusters.
-   **Federated Learning:** Enabling multiple MANTIS agents to share learned baselines without sharing raw data.

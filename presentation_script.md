# M.A.N.T.I.S. Interim Presentation & Demo Script

## Slide 1: Title Slide
**Visual:** M.A.N.T.I.S. Title Slide  
**Script:** "Hello everyone. My name is Anuskar Sigdel, and today I will be presenting my interim progress on M.A.N.T.I.S. — the Minimalist Alert Network for Threat Intelligence System, developed for my Level 6 Computing Dissertation."

## Slide 2: Introduction & Problem Statement
**Visual:** Background & Problem  
**Script:** "Current cybersecurity tools generally fall into two categories: signature-driven systems like Snort that miss unknown threats, and machine-learning XDR platforms like Wazuh that require huge amounts of RAM and dependencies like Java and Elastic. This leaves a gap for small Linux servers and IoT gateways which cannot afford these heavy resource costs. The problem I am solving is building an accurate, deployable, and zero-dependency Host-Based Intrusion Detection System (HIDS) for commodity hardware."

## Slide 3: Aim & Objectives
**Visual:** Aim & Objectives  
**Script:** "My overall aim is to design and evaluate this zero-dependency HIDS using only the Python standard library. My objectives include implementing five distinct mathematical detection engines, building a multithreaded raw-packet capture pipeline, integrating active iptables defence, and providing a SIEM dashboard. All of this must be trained and evaluated against real datasets."

## Slide 4: Literature & Comparable Systems
**Visual:** Literature & Comparable Systems  
**Script:** "My literature review highlights that while generative ML is accurate, its latency is too high for real-time blocking. Studies emphasize the need to benchmark both accuracy and latency together. When comparing mature systems, Snort and Suricata remain heavily signature-based and C++ dependent, Zeek doesn't block by default, and Wazuh is too heavy. MANTIS occupies the missing middle ground."

## Slide 5: Requirements Specification
**Visual:** Requirements Specification  
**Script:** "Functionally, the system must decode raw packets without third-party libraries like Scapy, route them through the five engines, and log alerts to a dashboard and SIEM. Non-functionally, it must maintain a latency of under 15 milliseconds per packet, consume less than 50 megabytes of RAM, and run purely on standard Python."

## Slide 6: System Analysis & Design
**Visual:** Architecture, Use Cases, Persistence  
**Script:** "The architecture features a multithreaded sniffer separated from the analysis engines by a bounded queue, ensuring no packet loss. Alerts are handled by a dispatcher for CSV, JSON, and active iptables defense. Persistence is managed via flat files for logs and a JSON 'brain' for the learned ML state—no SQL database is required."

## Slide 7: Detection Engines
**Visual:** The Five Engines  
**Script:** "Here is the core logic:  
1. **Z-Score** uses Welford's algorithm to detect volumetric floods.  
2. **K-Nearest Neighbours** uses distance-based classification for port scans.  
3. **Naive Bayes** tokenizes payloads to catch attacks like SQL injection.  
4. **Mini-Batch K-Means** clusters traffic to detect behavioural drift.  
5. **Bloom Filter** uses probabilistic hashing for instant blacklist matching."

## Slide 8: Implementation Progress
**Visual:** Progress (Interim)  
**Script:** "For the interim deliverable, the core functionality is complete. All five engines are written in pure Python. The sensor, dashboard, CSV logging, and active defence are active. Crucially, the system meets performance targets, registering only 9ms of latency and around 31MB of RAM usage."

---
## LIVE DEMONSTRATION 
*(Best done after Slide 8 or at the end)*

**Setup:**
- Open two terminal windows side-by-side (Terminal A for MANTIS, Terminal B for Attacker).
- Open a web browser to `http://localhost:8080`.

**Demo Script & Actions:**
1. **Start the Sensor & Dashboard:**
   - Run `sudo mantis` in Terminal A and select option `2`.
   - **Say:** *"I am now starting the MANTIS sensor in live mode, attached to the SIEM dashboard."*

2. **Demo 1: Port Scan (KNN Engine)**
   - Run `sudo nmap -sS -p 1-200 <VICTIM_IP>` in Terminal B.
   - **Say:** *"The attacker runs a stealth port scan. KNN classifies the rapid unique port connections and instantly flags a Port Scan Anomaly on the dashboard."*

3. **Demo 2: DDoS Attack (Z-Score Engine)**
   - Run `sudo hping3 -S --flood -p 80 <VICTIM_IP>` in Terminal B for 5 seconds.
   - **Say:** *"Now, a volumetric SYN flood. The Z-Score engine tracks the packets-per-second, sees it breach 3 standard deviations from the baseline, and flags a DDoS attack. Notice the CPU and RAM stay consistently low despite the flood."*

4. **Demo 3: SQL Injection (Naive Bayes)**
   - Run `curl "http://<VICTIM_IP>/?id=1%20UNION%20SELECT%20user,password"` in Terminal B.
   - **Say:** *"Finally, an application-layer attack. The Naive Bayes engine tokenizes the TCP payload and catches the SQL injection keywords, triggering an alert."*

---

## Slide 9: Evaluation & Testing Strategy
**Visual:** Evaluation Metrics  
**Script:** "To evaluate this, I am using a positivist quantitative approach measuring Precision, Recall, and F1 scores alongside performance metrics. I have built a 21-test V-Model unit suite to validate the math without needing raw sockets, and I am running offline benchmarks against the CIC-IoT2023 dataset."

## Slide 10: Conclusion & Next Steps
**Visual:** Conclusion & Next Steps  
**Script:** "To conclude, MANTIS successfully demonstrates that a zero-dependency HIDS is viable and performant. All interim requirements are met. Moving toward the final deliverable, I will validate the system against the complete CIC-IoT2023 dataset, refine the vocabulary for Naive Bayes, and conduct User Acceptance Testing. Thank you. I am happy to take any questions."

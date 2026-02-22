# Project Proposal: M.A.N.T.I.S. (Minimalist Alert Network for Threat Intelligence System)

## 1. Introduction

### Introduction
The rapid growth of the Internet of Things (IoT) and cloud networks has created a lot more opportunities for cyber attacks. Most traditional Intrusion Detection Systems (IDS) rely heavily on huge, closed-source libraries or just look for static, known signatures. These struggle to keep up with new, changing attacks. 

This project introduces MANTIS—a Host-Based Intrusion Detection System (HIDS) built from the ground up using "First Principles." Instead of relying on big commercial tools, MANTIS uses a hybrid detection engine that is specifically built to be lightweight, easy to understand, and capable of running without any outside dependencies. This makes it perfect for computers and networks that don't have a lot of processing power.

### Background
Right now, most IDSs fall into two main groups: signature-based models, which are fast but can't catch brand new attacks, and anomaly-based models, which are smarter but raise a lot of false alarms. Lately, the cybersecurity field has been moving towards hybrid systems. These combine the quick filtering of traditional methods with the smart adaptability of Machine Learning. However, a major issue with current student projects and open-source tools is that they just import big external ML libraries like Scikit-Learn. This hides how the actual math works and creates a "black box," where you don't really know how the system is making its decisions.

### Rationale
There is a real need for a transparent, educational IDS that actually shows the fundamental math behind threat detection. By building core algorithms—like Z-Score, K-Nearest Neighbors (KNN), and Naive Bayes—completely from scratch using just standard Python, this project balances performance with learning. It gives a clear view of exactly how a network packet is read and flagged as dangerous. This transparency is a huge advantage when it comes to security auditing, adjusting the system for specific networks, and academic research.

### Aim
The main goal is to design, code, and evaluate a lightweight, zero-dependency Host-Based Intrusion Detection System (HIDS). This system will use a layered engine made of statistical, behavioral, and probabilistic algorithms to detect network threats as they happen.

### Objectives
1. To build a raw socket sniffer that can capture and read TCP/IP packets directly at the Linux kernel level, without using third-party tools like Scapy.
2. To mathematically program five separate detection algorithms from first principles (Z-Score, KNN, Naive Bayes, Bloom Filter, and K-Means) to catch DDoS attacks, Port Scans, and malicious payloads.
3. To setup a distributed "Client-Server" architecture where individual MANTIS sensors send their alerts to a central SIEM dashboard using a custom UDP protocol.
4. To add active defense features (using `iptables`) so the system can automatically block malicious IP addresses.
5. To test the system's detection accuracy, speed, and CPU usage against live simulated attacks in a secure Linux virtual machine.

## 2. Literature Review

**Paper 1: "Rule-based with Machine Learning IDS for DDoS Attack Detection in CPPS" (IEEE Access, 2024)**
*   **Summary:** This paper looks at why we need a hybrid setup for intrusion detection. The authors suggest putting a fast, rule-based filter in front of a heavier Machine Learning (ML) layer. The main idea is to quickly drop known, massive attacks (like DDoS floods) early on. This saves a lot of processing power and lets the ML layer focus only on the tricky, confusing traffic.
*   **Relevance to MANTIS:** This effectively proves that MANTIS’s multi-stage pipeline is on the right track. MANTIS uses a quick probabilistic check (the Bloom Filter) to screen IP addresses before handing off the suspicious traffic to the heavier behavioral (KNN) and unsupervised (K-Means) engines. This confirms that dropping bad traffic early is standard practice to keep the system running fast.

**Paper 2: "An Analytical Study of Hybrid Machine Learning Techniques for Intrusion Detection in IoT" (IEEE, 2023)**
*   **Summary:** This research shows how combining different types of detection models lets a system catch a much wider variety of attacks—from huge floods to very slow, hidden scans. More importantly, it points out that for standard host computers or devices with limited memory, using lightweight hybrid algorithms is way better than trying to run massive Deep Learning models.
*   **Relevance to MANTIS:** Since MANTIS follows a strict "Zero-Dependency" rule, it uses only standard Python to keep its footprint small on a Linux host. Instead of importing heavy ML tools, MANTIS combines local statistical math (Z-Score) with behavioral math (KNN). This paper supports the idea that we can achieve great threat coverage with lightweight, custom-built algorithms instead of heavy external libraries.

**Paper 3: "Zero-Day Threat Detection: A Machine Learning Paradigm for Intrusion Prevention" (IEEE, 2024)**
*   **Summary:** This study tackles the danger of Zero-Day exploits—attacks nobody has seen before. The authors argue we need to move away from just looking for known attack signatures. Instead, they focus on Anomaly Detection, which means establishing a baseline of what "normal" network traffic looks like, and then flagging any weird deviations as potential new threats.
*   **Relevance to MANTIS:** This exact concept is the core logic behind MANTIS’s Phase 2 and Phase 3 engines. By writing custom Z-Score and K-Means clustering algorithms, MANTIS learns the normal behavior of the specific Linux machine it's installed on. This continuous learning approach validates our decision to focus on anomaly-based detection to catch brand new attacks.

**Paper 4: "Deep Learning with Metaheuristics Assisted Intrusion Detection on Cyber-Physical Smart Grids" (IEEE, 2024)**
*   **Summary:** This paper points out that default settings for algorithms usually don't work well because every network environment is different. The researchers highlight the importance of "parameter tuning," which means adjusting the internal math numbers so the detection model fits the specific traffic of the network it's monitoring.
*   **Relevance to MANTIS:** Maximum configurability is a huge part of MANTIS. Because we are coding the algorithms from scratch, we have total access to internal variables—like the 'k' in KNN or the threshold levels in the Z-Score. This paper proves that letting the user tweak these parameters is vital for lowering false alarms and making the IDS actually work well in real life.

## 3. Research Methodology

This project uses an **Agile Kanban** software development approach. Agile allows us to build the system iteratively, meaning we code, test, and adjust continuously rather than waiting until the end. The work is broken down into continuous "Sprints," focusing on delivering small, working pieces of the system step-by-step.

**Requirement Analysis (Backlog):** 
Setting up the strict "First Principles" rules, figuring out the math for the 5 chosen algorithms (Z-Score, KNN, Naive Bayes, Bloom Filter, K-Means), and preparing the Linux VM testing lab.

*   **Sprint 1: Core Foundation (The Sensor)**
    Coding the raw socket listener script (`sensor.py`) to capture and unpack live TCP/IP network traffic right at the kernel level, completely avoiding external packet tools.
*   **Sprint 2: Mathematical Detection Engines**
    Writing and testing the Statistical (DDoS) and Behavioral (Port Scan) detection algorithms from scratch, making sure the raw math works correctly on its own.
*   **Sprint 3: System Integration & Alerting**
    Connecting the independent detection modules into one smooth Sensor program, and creating the custom UDP messaging system to send threat alerts over the network.
*   **Sprint 4: Active Defense & SIEM Dashboard**
    Building the central SIEM web dashboard (`siem.py`) to visually display threats, and adding the Active Defense script (`active_defense.py`) to automate blocking bad IPs via the firewall.
*   **Sprint 5: Continuous Testing & Validation**
    Running simulated "Purple Teaming" attack tests using standard penetration tools against the local network. This checks the real-world accuracy, speed, and false-alarm rate of the finished system.

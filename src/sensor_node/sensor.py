#!/usr/bin/env python3
import socket
import struct
import sys
import time
import collections

import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import All Engines
import engines.z_score as z_score            # Phase 2: Statistical (DDoS)
import engines.knn as knn                    # Phase 3: Behavioral (Port Scan)
import engines.naive_bayes as naive_bayes    # Phase 4: Payload (SQLi/XSS)
import engines.bloom as bloom                # Phase 5: Reputation (Blacklist)
import engines.kmeans as kmeans              # Phase 6: Unsupervised Learning (Clustering)
import dashboard_ui.reporting as reporting   # Phase 7: Forensics (HTML Report)
import utils.active_defense as active_defense # Phase 8: Active Defense (Blocking)

# MANTIS: COMPLETE SENSOR AGENT (5 Algorithms + Forensics + IPS)
# Integrates all detection modules into a single real-time sensor.

def start_sensor(stats_queue=None, alert_queue=None):
    """
    Main Sensor Loop.
    Integrates all 5 Detection Algorithms + Active Blocking.
    """
    print("[*] MANTIS Sensor Starting (Full Mode)...")
    
    # --- INITIALIZE ENGINES ---
    stats_engine = z_score.MinimalistStats(window_size=30)
    knn_engine = knn.KNNMonitor(k=3)
    payload_engine = naive_bayes.PayloadMonitor()
    kmeans_engine = kmeans.KMeansMonitor(k=3)
    reporter = reporting.ReportGenerator()
    ips = active_defense.ActiveDefense() # Firewall Controller
    
    # Initialize Bloom Filter (Blacklist) with dummy data
    blacklist = bloom.BloomFilter(size=1000)
    blacklist.add("192.168.1.200") 
    blacklist.add("10.0.0.66")
    
    # State Tracking
    packet_count = 0
    unique_ports = set() # Track unique destination ports for KNN
    last_time = time.time()
    
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("[!] Error: Permission denied. You must run this script with sudo.")
        sys.exit(1)
        
    print("[*] API: 5 Engines Active. listening for threats...")
    print("[*] ACTIVE DEFENSE: Enabled (Will block attackers via iptables)")
    
    while True:
        try:
            raw_data, addr = s.recvfrom(65535)
            
            # --- GLOBAL TIMEKEEPING ---
            packet_count += 1
            current_time = time.time()
            
            # --- 1 SECOND TIMER (Behavioral & Statistical Checks) ---
            if current_time - last_time >= 1.0:
                # A. Z-Score (DDoS Detection)
                stats_engine.update(packet_count)
                mean, std_dev = stats_engine.calculate_baseline()
                z = 0.0
                if std_dev > 0:
                    z = (packet_count - mean) / std_dev
                
                # B. KNN (Port Scan Detection)
                feature_ports = len(unique_ports)
                knn_verdict, behavior_evidence = knn_engine.classify(feature_ports, packet_count)
                
                # C. K-Means (Traffic Clustering - Unsupervised)
                cluster_id = kmeans_engine.classify(packet_count, feature_ports)
                
                # D. Report Stats to Dashboard
                if stats_queue:
                    stats_queue.put({
                        'pps': packet_count,
                        'mean': mean,
                        'z_score': z
                    })
                
                # E. Generate Alerts (DDoS)
                if z > 3.0:
                    msg = f"DDoS DETECTED! Z-Score: {z:.2f} (PPS: {packet_count})"
                    reporter.add_alert(msg) 
                    if alert_queue: alert_queue.put(msg)
                    else: print(f"\n[!!!] {msg}")

                # F. Generate Alerts (Port Scan)
                if knn_verdict == "Scan":
                    msg = f"PORT SCAN DETECTED! (Unique Ports: {feature_ports}/sec)"
                    reporter.add_alert(msg)
                    if alert_queue: alert_queue.put(msg)
                    else: print(f"\n[!!!] {msg}")
                    
                # G. Generate Alerts (K-Means Anomaly)
                if cluster_id == 2 and knn_verdict != "Scan":
                    msg = f"ANOMALY DETECTED (Cluster 2)! Suspicious scan activity."
                
                # Reset Limits for next second
                packet_count = 0
                unique_ports.clear()
                last_time = current_time

            # --- PACKET PARSING & PAYLOAD ANALYSIS ---
            dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
            eth_proto = socket.ntohs(eth_proto)
            
            if eth_proto == 8: # IPv4
                ip_header = raw_data[14:34]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                # --- 4. BLOOM FILTER + ACTIVE DEFENSE (Reputation) ---
                if blacklist.check(s_addr):
                    msg = f"BLACKLISTED IP DETECTED: {s_addr} (Dropped)"
                    reporter.add_alert(msg)
                    if alert_queue: alert_queue.put(msg)
                    else: print(f"\n[!!!] {msg}")
                    continue # DROP PACKET

                t_offset = 14 + iph_length
                payload = b""
                
                if protocol == 6: # TCP
                    tcp_header = raw_data[t_offset:t_offset+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    dest_port = tcph[1]
                    unique_ports.add(dest_port)
                    
                    if not stats_queue: 
                        print(f"[TCP] {s_addr}:{tcph[0]} -> {d_addr}:{dest_port}")

                    data_offset = (tcph[4] >> 4) * 4
                    payload = raw_data[t_offset + data_offset:]
                    
                elif protocol == 17: # UDP
                    udp_header = raw_data[t_offset:t_offset+8]
                    udph = struct.unpack('!HHHH', udp_header)
                    src_port = udph[0]
                    dest_port = udph[1]
                    
                    # Ignore MANTIS's own SIEM Telemetry (Port 9999) to prevent infinite loops
                    if src_port == 9999 or dest_port == 9999:
                        continue
                        
                    unique_ports.add(dest_port)
                    
                    if not stats_queue: 
                        print(f"[UDP] {s_addr}:{src_port} -> {d_addr}:{dest_port}")

                    payload = raw_data[t_offset + 8:]
                
                # --- 5. PAYLOAD ANALYSIS (Naive Bayes) ---
                if payload:
                    verdict, score, bad_words = payload_engine.classify(payload)
                    if verdict == "Malicious":
                        msg = f"MALICIOUS PAYLOAD! Score: {score:.2f} Keywords: {bad_words}"
                        reporter.add_alert(msg)
                        if alert_queue: alert_queue.put(msg)
                        else: print(f"\n[!!!] {msg}")
                        
                        # --- TRIGGER ACTIVE DEFENSE (BLOCK IP) ---
                        # Only block on confirmed High-Confidence Payload Attacks
                        ips.block_ip(s_addr)

        except KeyboardInterrupt:
            print("\n[!] Stopping sniffer.")
            reporter.generate()
            break

if __name__ == "__main__":
    start_sensor()

# MANTIS Testing Guide
How to verify your system is working (and get that A+).

You need **TWO Terminals** (or two VMs).
- **Terminal A (Victim):** Running `sudo mantis`
- **Terminal B (Attacker):** Running the attack commands below.

## Test 1: DDoS Detection (Z-Score Engine)
**Goal:** Trigger a "Volumetric Anomaly" alert.
**Command (Attacker):**
```bash
# Ping Flood (Simple)
sudo ping -f <VICTIM_IP>

# OR SYN Flood (Advanced - Install hping3 first)
sudo hping3 -S --flood -p 80 <VICTIM_IP>
```
**Expected Result:**
Dashboard turns **RED**. "SYSTEM STATUS: UNDER ATTACK (DDoS)".

## Test 2: Port Scan Detection (KNN Engine)
**Goal:** Trigger a "Port Scan" alert.
**Command (Attacker):**
```bash
# Stealth Syn Scan on top 100 ports
sudo nmap -sS -p 1-100 <VICTIM_IP>
```
**Expected Result:**
Alert Log shows: `Port Scan Detected from <ATTACKER_IP> | Hit 100 Ports`.

## Test 3: SQL Injection Detection (Naive Bayes Engine)
**Goal:** Trigger a "Payload Anomaly" alert.
**Command (Attacker):**
```bash
# Send a fake malicious HTTP request
# Send a fake malicious HTTP request (Use %20 for spaces!)
curl "http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%20user,password%20FROM%20users"

# Alternative: Netcat Method (Guaranteed to work locally)
# Terminal 1: nc -l -p 8080
# Terminal 2: curl "http://127.0.0.1:8080/index.php?id=1%20UNION%20SELECT%201,2,3"
```
**Expected Result:**
Alert Log shows: `Payload Anomaly (SQLi/XSS) ... Keywords: ['UNION', 'SELECT']`.

## Test 4: Blacklist Detection (Bloom Filter)
**Goal:** Trigger a "Blacklisted IP" alert.
**Steps:**
1.  Open `sensor.py` on the Victim machine.
2.  Add **YOUR Attacker IP** to the `blacklist` list (Line ~115).
3.  Restart MANTIS.
4.  Send *any* packet (e.g., `ping <VICTIM_IP>`).
**Expected Result:**
Alert Log shows: `BLACKLISTED IP DETECTED: <ATTACKER_IP> (Dropped)`.

## Test 5: Enterprise SIEM Dashboard (Phase 8)
**Goal:** Verify the Web-Based Dashboard receives alerts.
**Steps:**
1.  **VM 1 (SIEM):** Run `python3 siem.py`.
2.  **Browser:** Open `http://localhost:8080`. You should see the login/dashboard.
3.  **VM 2 (Sensor):** Run `sudo python3 main.py --remote <VM1_IP>`.
4.  **Attack VM 2:** Run `curl "http://<VM2_IP>/?id=UNION SELECT"`.
**Expected Result:**
The alert appears **instantly** on the Web Dashboard table.

## Test 6: Advanced ML & Reporting (Phase 6/7)
**Goal:** Verify K-Means Clustering and Report Generation.
1.  **Run MANTIS:** `sudo mantis`
2.  **Generate Traffic:** Browse heavy sites (Youtube/CNN) to train K-Means.
3.  **Stop MANTIS:** Press `Ctrl+C`.
4.  **Check Report:** Open `mantis_report.html` in your browser.
    *   It should show a professional Incident Log.
    *   Look for "ANOMALY DETECTED (Cluster 2)" alerts if you scanned yourself.

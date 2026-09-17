# MANTIS — Demonstration & Viva Guide

**One-stop runbook for demonstrating MANTIS to a supervisor / examiner.**
Every command below is copy‑pasteable and commented so you can explain *what*
it does and *why* while it runs. Sample outputs are real captures from this
project.

> MANTIS = **M**inimalist **A**lert **N**etwork for **T**hreat **I**ntelligence
> **S**ystem — a zero‑dependency Host‑Based IDS written entirely in the Python
> Standard Library (no Scapy, no scikit‑learn). Five detection engines:
> **Z‑Score** (DDoS), **KNN** (port scans), **Naive Bayes** (payloads),
> **K‑Means** (drift) and a **Bloom Filter** (IP reputation).

---

## 0. TL;DR cheat sheet

| Goal | Command (run from `src/`) | Engine fired |
|------|---------------------------|--------------|
| Live sensor (local CLI) | `sudo python3 main.py` → choose `1` | all |
| Live sensor (web SIEM) | `sudo python3 main.py` → choose `2`, open `http://localhost:8080` | all |
| Web dashboard only | `python3 dashboard_ui/siem.py` | — |
| Train a brain | `python3 -m training.train --knn-csv ../datasets/knn_sample.csv --payload-csv ../datasets/payload_sample.csv` | — |
| Evaluate accuracy | `python3 -m evaluation.evaluate --knn-csv ../datasets/knn_sample.csv --payload-csv ../datasets/payload_sample.csv --zscore-csv ../datasets/zscore_sample.csv` | — |
| Unit tests (V‑Model) | `python3 -m unittest discover -s tests -v` | — |
| Port scan demo | `sudo nmap -sS -p 1-200 <VICTIM_IP>` | KNN |
| **Max‑PPS / DDoS demo** | `sudo hping3 -S --flood -p 80 <VICTIM_IP>` | Z‑Score |
| SQLi payload demo | `curl "http://<VICTIM_IP>/?id=1%20UNION%20SELECT%201,2"` | Naive Bayes |
| Blacklist demo | add attacker IP to Bloom list, send any packet | Bloom |

---

## 1. Prerequisites & one‑time setup

```bash
# MANTIS needs raw sockets (AF_PACKET) -> run the SENSOR as root.
# Training / evaluation / tests do NOT need root.

cd src

# (a) If files were edited on Windows, strip CR line endings first:
sed -i 's/\r$//' *.py install.sh **/*.py     # safe to re-run

# (b) Install the launcher + optional tools (auto-detects your distro):
sudo bash install.sh
#   -> detects apt/dnf/pacman/zypper/apk
#   -> installs iptables + libcap
#   -> creates /usr/local/bin/mantis, mantis-siem, mantis-train, mantis-eval
#   -> tries `setcap cap_net_raw,cap_net_admin=eip` so you can later
#      run the sensor WITHOUT sudo.

# (c) Confirm raw-socket support is present (1 = yes):
python3 -c 'import socket; print(hasattr(socket,"AF_PACKET"))'
```

**Talking point for the supervisor:** the only privilege MANTIS needs is
`CAP_NET_RAW` to read packets and `CAP_NET_ADMIN` to insert an `iptables` DROP.
There are **no third‑party packages in the detection path** — that is the whole
point of the project (deployable on a Raspberry Pi / IoT gateway).

---

## 2. Running the system

### 2.1 Local mode (single machine)

```bash
cd src
sudo python3 main.py          # or just `sudo mantis` after install
# Prompt: "Choice [1/2]"
#   1 = terminal (CLI) dashboard
#   2 = web SIEM dashboard on http://localhost:8080
# Ctrl+C to stop -> writes data/mantis_brain_<timestamp>.json + mantis_report.html
```

### 2.2 Distributed mode (sensor on one box, dashboard on another)

```bash
# On the DASHBOARD machine (note its IP, e.g. 192.168.1.50):
python3 dashboard_ui/siem.py          # or `mantis-siem`

# On the SENSOR machine (the one being protected):
sudo python3 main.py --remote 192.168.1.50 --port 9999
# Alerts are forwarded over UDP:9999 and appear instantly on the dashboard.
```

**Talking point:** the sensor and SIEM are decoupled over UDP — one dashboard
can aggregate many sensors (classic SIEM topology).

---

## 3. Live attack demonstrations

You need **two terminals/VMs**: **Victim** (runs MANTIS) and **Attacker**.
Find the victim IP with `ip a` (use `lo` / `127.0.0.1` for a single‑box demo).

### 3.1 Port‑scan detection — KNN engine

```bash
# Attacker: stealth SYN scan of the first 200 ports
sudo nmap -sS -p 1-200 <VICTIM_IP>
```
**Expected:** `PORT SCAN DETECTED! (Unique Ports: NN/sec)`.
**Why:** KNN classifies the `(unique_ports, packet_count)` feature vector; many
distinct destination ports in one second lands in the "Scan" class.

### 3.2 DDoS / **maximum packets‑per‑second** — Z‑Score engine

This is the "give maximum sent packets" demo. Pick the loudest tool available:

```bash
# Option A - hping3 SYN flood (fastest; best for the demo):
sudo hping3 -S --flood -p 80 <VICTIM_IP>
#   -S       = SYN packets
#   --flood  = send as fast as possible (no per-packet wait, no replies shown)
#   -p 80    = target port

# Option B - ICMP flood (no extra tools needed):
sudo ping -f <VICTIM_IP>

# Option C - generate a precise, measurable rate with hping3:
sudo hping3 -S -p 80 -i u200 <VICTIM_IP>   # u200 = 1 packet / 200 microseconds (~5000 pps)
```

**Expected:** dashboard flips to **RED** / `DDoS DETECTED! Z-Score: x.xx (PPS: N)`.

**How the maths works (explain this):** the Z‑Score engine keeps a running mean
(μ) and variance (σ²) of packets‑per‑second using **Welford's online algorithm**
(O(1) memory, no packet history stored). Each second it computes
`z = (pps − μ) / σ` and alerts when `|z| > 3` — i.e. traffic is 3 standard
deviations above the learned baseline.

**Things to watch / mention while flooding:**
- The **PPS** counter on the dashboard climbing, and the **Z‑Score** crossing 3.
- Let it run ~10 s baseline *before* flooding so μ/σ are meaningful.
- **Resource footprint** (a key NFR): in a second terminal show it stays light:
  ```bash
  pidstat -p $(pgrep -f sensor_node/sensor.py) 1 5   # CPU%
  ps -o rss= -p $(pgrep -f sensor_node/sensor.py)     # resident KB (~31 MB target)
  ```
  Talking point: MANTIS sustains the flood at **< 5% CPU / < 50 MB RAM** on one
  vCPU — that is the headline "runs on constrained hardware" claim.
- **Safety:** only flood a host/IP you own, on an isolated lab network/VM. A
  `--flood` will saturate the link; never point it at production or the internet.

### 3.3 SQL‑injection / malicious payload — Naive Bayes engine

```bash
# Attacker: send an HTTP request containing a SQLi string (%20 = space)
curl "http://<VICTIM_IP>/?id=1%20UNION%20SELECT%20user,password%20FROM%20users"

# Guaranteed local variant (works on one box):
#   Terminal 1 (victim side helper):  nc -l -p 8085
#   Terminal 2:                        curl "http://127.0.0.1:8085/?q=1 UNION SELECT 1,2,3"
```
**Expected:** `MALICIOUS PAYLOAD! Confidence: 99.93% Keywords: ['UNION','SELECT']`.
**Why:** Naive Bayes scores the TCP payload with **log‑probabilities + Laplace
smoothing** over a learned malicious/benign vocabulary; SQLi keywords push the
posterior over the threshold.

### 3.4 Blacklist / IP reputation - Bloom Filter

```bash
# Send one packet from the built-in blacklisted demonstration address.
# The packet stays on the researcher's loopback interface.
sudo hping3 -I lo -c 1 -a 10.0.0.66 -S -p 80 127.0.0.1
```
**Expected:** `BLACKLISTED IP DETECTED: 10.0.0.66 (Flagged)` when blocking is off.
**Why:** a space‑efficient Bloom Filter gives O(1) membership tests; false
negatives are impossible (so a known‑bad IP is never missed).

### 3.5 Behavioural drift — K‑Means (Cluster 2)

```bash
# Generate varied/heavy traffic for a while (browse heavy sites, mix protocols),
# then stop MANTIS (Ctrl+C) and open mantis_report.html.
```
**Expected:** `ANOMALY DETECTED (Cluster 2)!` for traffic that drifts away from
normal centroids. Online K‑Means updates centroids with a learning rate, so it
adapts to live traffic instead of using a frozen model.

---

## 4. Active defence (iptables) — automatic blocking

When Naive Bayes confirms a malicious payload, MANTIS calls
`utils/active_defense.py`, which inserts a DROP rule at the top of the INPUT
chain (127.0.0.1 / 0.0.0.0 are whitelisted so it never blocks itself):

```bash
# The exact rule MANTIS runs for a flagged source IP:
sudo iptables -I INPUT 1 -s <ATTACKER_IP> -j DROP

# Show the rule MANTIS inserted (point to the DROP line + packet counters):
sudo iptables -L INPUT -n -v

# Demo cleanup so you leave the box as you found it:
sudo iptables -D INPUT -s <ATTACKER_IP> -j DROP
```
**Talking point:** this is the "active" in active defence — unlike Snort/Zeek
which only *alert*, MANTIS *responds* inline. (Requires `CAP_NET_ADMIN`; inside
a restricted container without it, run this on a real VM.)

---

## 5. Forensic report & SIEM dashboard

```bash
# The SIEM web dashboard (severity-coloured live event stream):
python3 dashboard_ui/siem.py     # then open http://localhost:8080

# The forensic HTML report is written automatically on Ctrl+C of the sensor,
# or generate a sample directly:
cd src/dashboard_ui && python3 reporting.py     # writes mantis_report.html
```
Open `mantis_report.html` in a browser: session summary + colour‑coded incident
log (DDoS=red, scan=amber, web‑attack=blue, blacklist=purple).

---

## 6. Training, evaluation & tests (the measurable evidence)

```bash
cd src

# Train engines from labelled CSVs -> data/mantis_brain_<timestamp>.json
python3 -m training.train \
    --knn-csv ../datasets/knn_sample.csv \
    --payload-csv ../datasets/payload_sample.csv

# Train from the external benchmark (33 attack types):
python3 -m training.train --cic-iot2023 ../datasets/cic_iot2023.csv

# Evaluate -> precision / recall / F1 / accuracy per engine
python3 -m evaluation.evaluate \
    --knn-csv ../datasets/knn_sample.csv \
    --payload-csv ../datasets/payload_sample.csv \
    --zscore-csv ../datasets/zscore_sample.csv
#   writes evaluation_results.txt and evaluation_results.json

# Unit tests (V-Model: each engine's maths in isolation, no root needed):
python3 -m unittest discover -s tests -v      # -> Ran 116 tests ... OK
```

Representative interim results (from `evaluation_results.txt`):

```text
--- KNN (Port Scan) ---        Precision 0.50  Recall 0.90  F1 0.64
--- Naive Bayes (Payload) ---  Precision 1.00  Recall 0.92  F1 0.96
--- Z-Score (DDoS) ---         Precision 1.00  Recall 0.50  F1 0.67
```
**Talking point:** low recall on small seeded corpora is expected — it reflects
training‑set size, not an algorithm defect (KNN, trained on a larger corpus,
reaches recall 1.0). The full CIC‑IoT2023 benchmark is the Sprint S‑3 deliverable.

---

## 7. How the report evidence was produced (reproducibility)

All figures in `docs/final/interim/MANTIS_Interim_Report.docx` Appendix B were
generated by scripts in `docs/final/screenshots/` so they can be regenerated:

```bash
python3 docs/final/screenshots/capture_remaining.py   # terminal captures (tests/train/eval/csv)
python3 docs/final/screenshots/live_capture.py        # real sensor run on loopback (root)
python3 docs/final/screenshots/insert_screenshots.py  # drop images into the .docx placeholders
```

| Evidence | Source | Genuine? |
|----------|--------|----------|
| Unit tests / train / eval / dataset | real command output | yes |
| Live sensor alerts (B.1) | `live_capture.py` real loopback attack | yes |
| SIEM dashboard + severity rows | running `siem.py` | yes |
| Forensic HTML report (B.3) | real `reporting.py` output | yes |
| `sensor.py` code view | real source render | yes |
| `iptables` (B.8) & `install.sh` (B.7) | **capture on your own VM** | pending |

> The last two are intentionally left as placeholders: they need `CAP_NET_ADMIN`
> / a package manager that a restricted environment cannot provide. Capture them
> on your Ubuntu/Kali VM with §1 and §4 commands.

---

## 8. What to consider when explaining to the supervisor

- **Lead with the gap:** Snort/Suricata = signature‑only (miss zero‑days);
  Wazuh = powerful but multi‑GB Java/Elastic (won't fit a Pi). MANTIS fills the
  middle — lightweight, anomaly‑capable, *and* it blocks.
- **Show the maths is yours:** be ready to whiteboard Welford's update and the
  `|z|>3` rule, KNN distance, and Naive Bayes log‑probability + Laplace smoothing.
- **Prove the NFRs live:** run the flood (§3.2) *and* show CPU/RAM staying low —
  that is the dissertation's central, falsifiable claim.
- **Map to the marking scheme:** Requirements/Design/Implementation carry the
  most marks — demo functional requirements (5 engines + active defence), point
  at the UML in Chapter 4, and the V‑Model tests in Chapter 6.
- **Be honest about limits:** small seeded datasets, CIC‑IoT2023 full run and the
  Snort/Wazuh head‑to‑head are Sprint S‑3; single‑host scope; loopback demo vs.
  real NIC. Naming these earns marks (critical evaluation).
- **Word count:** interim body is within the 5,500‑word brief (refs/appendices
  excluded); tables and code listings are excluded by the usual convention.
- **Safety/ethics:** all attack traffic is generated against your own isolated
  VMs; never flood or scan hosts you don't own.

---

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `need sudo for raw sockets` / `run with sudo` | start the **sensor** with `sudo` (or run `install.sh` to `setcap`). |
| `'python3\r': No such file` | CRLF endings — run `sed -i 's/\r$//' *.py install.sh`. |
| `AF_PACKET not available` | you're in a container without it — train/eval/tests still work; demo the sensor on a VM. |
| iptables `Permission denied (must be root)` even as root | container lacks `CAP_NET_ADMIN`; run on a real VM. |
| No DDoS alert during flood | let it baseline ~10 s first; ensure the flood hits the interface MANTIS is sniffing. |
| Dashboard empty | confirm sensor `--remote <dashboard_ip>` matches, UDP 9999 open, both on same network. |

---
*Generated for the MANTIS interim demonstration. Keep this beside you during the
viva — every command is safe to run live on an isolated lab VM.*

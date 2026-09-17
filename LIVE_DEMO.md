# MANTIS — Live Demo & Test Command Sheet

**One file. Every command. Copy-paste to train, test, evaluate, and demo live.**

Use this beside you during a supervisor meeting, viva, or lab demo.
All paths assume you start from the project folder `mantis/`.

---

## Your network (use these IPs for attacks)

From your machine (`ip a`):

| Interface | State | IP | Use for attacks? |
|-----------|-------|-----|------------------|
| **lo** | UP | `127.0.0.1` | Same-machine demo (loopback) |
| **eth0** | DOWN (no cable) | — | **Do not use** |
| **wlan0** | UP (Wi-Fi) | **`192.168.196.228`** | **Main victim IP** — MANTIS on this laptop |

**Which IP to use:**

```bash
# Same laptop (MANTIS + attacks on one machine) — RECOMMENDED:
sudo ./demo_all_attacks.sh              # auto-picks 192.168.196.228 via wlan0
sudo ./demo_all_attacks.sh lo           # loopback only (127.0.0.1)

# Explicit Wi-Fi IP:
sudo ./demo_all_attacks.sh 192.168.196.228

# Another phone/laptop on same Wi-Fi attacking this machine:
sudo nmap -sS -p 1-200 192.168.196.228
sudo hping3 -S --flood -p 80 192.168.196.228

# SIEM dashboard in browser (on this laptop):
http://127.0.0.1:8080
# or from another device on LAN:
http://192.168.196.228:8080
```

Check IP anytime:

```bash
ip -4 addr show wlan0 | grep inet
ip -4 route get 1.1.1.1 | grep src
```

---

## Quick reference

| Goal | Command | Root? |
|------|---------|-------|
| **Full benchmark (best for supervisor)** | `cd src && ./benchmark.sh` | No |
| **Max packet flood (DDoS demo)** | `sudo hping3 -S --flood -p 80 <VICTIM_IP>` | Yes |
| **All 3 models — live attacks** | `cd src && sudo ./demo_all_attacks.sh` | Yes |
| **All 3 models — live (loopback)** | `cd src && sudo ./demo_all_attacks.sh lo` | Yes |
| **Max flood on your Wi-Fi IP** | `sudo hping3 -S --flood -p 80 192.168.196.228` | Yes |
| **All 3 models — offline scores** | `cd src && ./benchmark.sh` | No |
| Install system | `cd src && sudo ./install.sh` | Yes |
| Unit tests (116 tests) | `cd src && python3 -m unittest discover -s tests -v` | No |
| Train 3 models | see §3 | No |
| Evaluate scores | see §4 | No |
| Live sensor + dashboard | `cd src && sudo python3 main.py` | Yes |
| Web SIEM only | `cd src && python3 dashboard_ui/siem.py` | No |

---

## 0. First-time fix (Windows-edited files)

If you see `'python3\r': No such file` or `bad interpreter`:

```bash
cd src
sed -i 's/\r$//' *.py install.sh benchmark.sh **/*.py
chmod +x install.sh benchmark.sh
```

Check Python and raw sockets:

```bash
python3 --version
python3 -c 'import socket; print("AF_PACKET:", hasattr(socket, "AF_PACKET"))'
```

---

## 1. Install (one time)

```bash
cd src
sudo ./install.sh
```

After install these commands work from anywhere:

```bash
mantis              # live sensor
mantis-siem         # web dashboard
mantis-train --help
mantis-eval --help
mantis-benchmark    # train + test + report
```

Help:

```bash
mantis --help
```

---

## 2. ONE COMMAND — train, test, evaluate, compare (show supervisor first)

**This is the main demo command.** No sudo. Takes ~10 seconds.

```bash
cd src
./benchmark.sh
```

What it does:

1. Runs **116 automated tests** (V-Model - validates the complete pipeline)
2. **Trains 3 models** — KNN + K-Means (CIC-IoT2023) + Naive Bayes (payload CSV)
3. **Evaluates** KNN, Naive Bayes, Z-Score on labelled test CSVs
4. Writes a **supervisor comparison report**

### Show the results

```bash
cd src
cat benchmark_report.txt
cat evaluation_results.txt
cat evaluation_results.json
ls -lt data/mantis_brain_*.json | head -3
```

### Files created

| File | What it is |
|------|------------|
| `data/mantis_brain_<timestamp>.json` | All 3 trained models |
| `evaluation_results.txt` | Precision / Recall / F1 table |
| `evaluation_results.json` | Raw TP/FP/FN/TN numbers (proof) |
| `benchmark_report.txt` | Full comparison + supervisor Q&A |

---

## 3. Train models (manual — if asked separately)

All commands run from `src/`. No root.

### Train all 3 models at once (recommended)

```bash
cd src
python3 -m training.train \
    --cic-iot2023 ../datasets/cic_iot2023.csv \
    --payload-csv ../datasets/payload_sample.csv \
    --out data/mantis_brain.json
```

### Train individually

```bash
cd src

# KNN only
python3 -m training.train --knn-csv ../datasets/knn_sample.csv

# Naive Bayes only
python3 -m training.train --payload-csv ../datasets/payload_sample.csv

# KNN + K-Means from CIC-IoT2023
python3 -m training.train --cic-iot2023 ../datasets/cic_iot2023.csv
```

### Check what was trained

```bash
cd src
python3 -c "
import json, glob
f = sorted(glob.glob('data/mantis_brain_*.json'))[-1]
d = json.load(open(f))
print('Brain:', f)
print('Models:', [k for k in d if not k.startswith('_')])
print('Meta:', d.get('_meta'))
"
```

---

## 4. Evaluate — how Precision / Recall / F1 are calculated

### Run evaluation

```bash
cd src
python3 -m evaluation.evaluate \
    --brain data/mantis_brain_20260603_095424.json \
    --knn-csv ../datasets/knn_sample.csv \
    --payload-csv ../datasets/payload_sample.csv \
    --zscore-csv ../datasets/zscore_sample.csv
```

Use the latest brain file (or omit `--brain` to auto-pick newest):

```bash
cd src
BRAIN=$(ls -t data/mantis_brain_*.json | head -1)
python3 -m evaluation.evaluate \
    --brain "$BRAIN" \
    --knn-csv ../datasets/knn_sample.csv \
    --payload-csv ../datasets/payload_sample.csv \
    --zscore-csv ../datasets/zscore_sample.csv
```

### Read scores

```bash
cd src
cat evaluation_results.txt
```

### Explain the maths (say this to supervisor)

```
For each test row:
  prediction = engine.classify(features)
  compare prediction vs true label in CSV

Confusion matrix:
  TP = attack row, model said attack     (correct alert)
  FP = normal row, model said attack     (false alarm)
  FN = attack row, model said normal     (missed attack)
  TN = normal row, model said normal     (correct silence)

Precision = TP / (TP + FP)   → "when it alerts, is it right?"
Recall    = TP / (TP + FN)   → "did we catch the attacks?"
F1        = 2 × P × R / (P + R)  → balanced score (primary metric)
```

Example from latest run:

| Engine | TP | FP | FN | TN | Precision | Recall | F1 |
|--------|----|----|----|-----|-----------|--------|-----|
| Naive Bayes | 6 | 0 | 6 | 12 | 100% | 50% | 0.67 |
| Z-Score | 3 | 0 | 3 | 34 | 100% | 50% | 0.67 |
| KNN | 18 | 19 | 3 | 0 | 49% | 86% | 0.62 |

Naive Bayes worked example:

```
Precision = 6 / (6 + 0) = 100%
Recall    = 6 / (6 + 6) = 50%
F1        = 2 × 1.0 × 0.5 / (1.0 + 0.5) = 0.67
```

---

## 5. Unit tests (V-Model — no network, no root)

```bash
cd src
python3 -m unittest discover -s tests -v
```

Expected ending:

```
Ran 116 tests in ...
OK
```

What is tested:

| Test group | Engine |
|------------|--------|
| `test_engines.TestZScore` | Z-Score maths |
| `test_engines.TestKNN` | KNN distance + classify |
| `test_engines.TestNaiveBayes` | Payload scoring |
| `test_engines.TestKMeans` | Cluster assignment |
| `test_engines.TestBloom` | Blacklist lookup |
| `test_training_and_eval.*` | Train + eval pipeline |

---

## 6. Live sensor demo (needs root or install.sh setcap)

### Setup — two terminals

| Terminal | Role | Command |
|----------|------|---------|
| **A (Victim)** | Run MANTIS | `cd src && sudo python3 main.py` |
| **B (Attacker)** | Run attacks | commands in §6 below |

Choose option `1` for CLI dashboard or `2` for web SIEM at `http://localhost:8080`.

Single machine: use **`192.168.196.228`** (wlan0) or **`lo`** for loopback (`sudo ./demo_all_attacks.sh lo`).

Find your IP anytime:

```bash
ip -4 addr show wlan0 | grep inet
# inet 192.168.196.228/22 ...
```

### Demo 1 — Port scan (KNN engine)

**Terminal A:** MANTIS running

**Terminal B:**

```bash
# Same machine — Wi-Fi IP (matches MANTIS on wlan0 traffic)
sudo nmap -sS -p 1-200 192.168.196.228

# Or loopback
sudo nmap -sS -p 1-200 127.0.0.1
```

**Expected:** `PORT SCAN DETECTED!`

**Say:** *"KNN classifies unique ports vs packet count. Many ports in one second = scan behaviour."*

---

### Demo 2 — Maximum packet flood / DDoS (Z-Score engine)

**What supervisor asked for:** send the **maximum number of packets** to the victim IP
so MANTIS sees a traffic spike and triggers the Z-Score DDoS alert.

**Before you attack:**
1. Start MANTIS on the victim and wait **~10 seconds** (baseline learning).
2. Replace `<VICTIM_IP>` with **`192.168.196.228`** (wlan0) or `127.0.0.1` (lo).
3. **Only attack your own lab VM** — never the internet or production hosts.

---

#### Option A — MAXIMUM packets (best for supervisor demo) ⭐

```bash
# ── MAXIMUM SYN FLOOD — sends packets as fast as the CPU/network allows ──
#
# sudo          → raw packets need root (same as nmap -sS)
# hping3        → tool to craft and send custom TCP/UDP/ICMP packets
# -S            → SYN flag only (TCP handshake step 1 — looks like connection attempts)
# --flood       → NO delay between packets = MAXIMUM send rate (fastest possible)
#                 hping3 ignores replies and keeps sending until you press Ctrl+C
# -p 80         → target port 80 (HTTP — common demo port; any open port works)
# <VICTIM_IP>   → 192.168.196.228 (your wlan0) or 127.0.0.1 (lo)
#
# What happens:
#   Attacker → thousands of SYN packets/sec → Victim NIC → MANTIS sensor counts PPS
#   Z-Score: z = (current_PPS - mean) / std_dev  →  alert when z > 3
#
# Stop attack:  Ctrl+C
# Safety:        isolated VM only — --flood will saturate the link

sudo hping3 -S --flood -p 80 <VICTIM_IP>
```

**One-box example (same laptop, victim = localhost):**

```bash
sudo hping3 -S --flood -p 80 192.168.196.228
# or loopback:
sudo hping3 -S --flood -p 80 127.0.0.1
```

**Expected on MANTIS dashboard:**

```
DDoS DETECTED! Z-Score: 4.xx (PPS: 8500)
SYSTEM STATUS: UNDER ATTACK (DDoS)
```

**Say to supervisor:** *"This sends the maximum packets per second. MANTIS counts
packets-per-second, compares to its learned baseline, and alerts when traffic is
more than 3 standard deviations above normal."*

---

#### Option B — ICMP flood (max ping rate, no extra install)

```bash
# ping -f  → flood mode: send ICMP echo requests as fast as possible (like hping3 --flood)
#            requires root; stops with Ctrl+C
#
# Good if hping3 is not installed:  sudo apt install hping3

sudo ping -f <VICTIM_IP>
```

---

#### Option C — Controlled high rate (measurable PPS, not absolute max)

Use this if `--flood` is too aggressive or you want to quote an exact rate:

```bash
# -i u200  → interval 200 microseconds between packets ≈ 5000 packets/second
#            (1 second = 1,000,000 μs → 1,000,000 / 200 = 5000 pps)
# No --flood → sends at a fixed measurable rate instead of unlimited max

sudo hping3 -S -p 80 -i u200 <VICTIM_IP>
```

---

#### Option D — Flood a specific victim IP on your lab network (two VMs)

```bash
# Your laptop Wi-Fi IP (wlan0 UP):
ip -4 addr show wlan0 | grep inet

# Terminal A — start MANTIS, wait 10 sec baseline

# Terminal B — max flood to wlan0 IP:
sudo hping3 -S --flood -p 80 192.168.196.228
```

---

**Show MANTIS stays lightweight while under max flood (Terminal C):**

```bash
# pidstat → show CPU % every 1 sec, 5 samples, for the MANTIS sensor process
pidstat -p $(pgrep -f sensor.py) 1 5

# ps rss → resident memory in KB (~32000 = ~31 MB)
ps -o rss= -p $(pgrep -f sensor.py)
```

**Say:** *"Even under maximum packet flood, CPU stays under 5% and RAM ~31 MB."*

**Stop the flood:** `Ctrl+C` in the attacker terminal.

---

### Demo 2B — ALL 3 models in ONE command (live attacks) ⭐

**Two terminals needed:**

**Terminal A — start MANTIS first, wait ~10 seconds:**

```bash
cd src
sudo python3 main.py
# choose 1 (CLI) or 2 (web dashboard)
```

**Terminal B — run all 3 attacks (auto uses wlan0 `192.168.196.228`):**

```bash
cd src
sudo ./demo_all_attacks.sh
```

**Loopback only:**

```bash
sudo ./demo_all_attacks.sh lo
```

**Explicit IP + 8 sec flood:**

```bash
sudo ./demo_all_attacks.sh 192.168.196.228 8
```

| Step | What runs | Model | Expected on MANTIS |
|------|-----------|-------|-------------------|
| 1 | `nmap -sS -p 1-200` | **KNN** | PORT SCAN DETECTED |
| 2 | `hping3 -S --flood -p 80` (5s) | **Z-Score** | DDoS DETECTED |
| 3 | `curl ... UNION SELECT ...` | **Naive Bayes** | MALICIOUS PAYLOAD |

**Say:** *"One script fires port scan, maximum flood, and SQLi — each tests a different trained model."*

---

### Demo 2C — ALL 3 models in ONE command (offline scores, no attacks)

No root, no second terminal — trains and scores all 3 engines on CSV data:

```bash
cd src
./benchmark.sh
cat benchmark_report.txt
```

---

### Demo 3 — SQL injection (Naive Bayes engine)

**One-box guaranteed method:**

**Terminal B — listener:**

```bash
nc -l -p 8085
```

**Terminal C — attack:**

```bash
curl "http://127.0.0.1:8085/?id=1%20UNION%20SELECT%20user,password%20FROM%20users"
```

**Expected:** `MALICIOUS PAYLOAD!` with keywords `UNION`, `SELECT`

**Say:** *"Naive Bayes scores payload text with log-probabilities + Laplace smoothing."*

---

### Demo 4 - Blacklist (Bloom Filter engine)

With MANTIS running and blocking disabled, send one packet from the built-in
demonstration address over loopback:

```bash
sudo hping3 -I lo -c 1 -a 10.0.0.66 -S -p 80 127.0.0.1
```

**Expected:** `BLACKLISTED IP DETECTED: 10.0.0.66 (Flagged)` when blocking is off.

**Say:** *"Bloom Filter gives O(1) IP lookup with minimal memory."*

---

### Demo 5 - Stop sensor -> forensic report

**Terminal A:** press `Ctrl+C`

```bash
cd src
ls -la mantis_report.html data/mantis_brain_*.json mantis_logs.csv
xdg-open mantis_report.html
```

**Expected:** HTML incident log with colour-coded alerts.

---

## 7. Web SIEM dashboard (distributed mode)

### Terminal 1 — Dashboard server

```bash
cd src
python3 dashboard_ui/siem.py
```

Open browser: **http://localhost:8080**

### Terminal 2 — Sensor (replace IP with dashboard machine IP)

```bash
cd src
sudo python3 main.py --remote 127.0.0.1 --port 9999
```

### Terminal 3 — Attack

```bash
curl "http://127.0.0.1/?id=1%20UNION%20SELECT%201,2"
sudo nmap -sS -p 1-100 127.0.0.1
```

**Expected:** Alerts appear instantly on web dashboard.

---

## 8. Active defence (iptables — optional, needs root + CAP_NET_ADMIN)

When Naive Bayes confirms malicious payload, MANTIS inserts:

```bash
sudo iptables -I INPUT 1 -s <ATTACKER_IP> -j DROP
```

Show rule:

```bash
sudo iptables -L INPUT -n -v
```

Clean up after demo:

```bash
sudo iptables -D INPUT -s <ATTACKER_IP> -j DROP
```

---

## 9. Datasets used

| File | Rows | Used for |
|------|------|----------|
| `datasets/cic_iot2023.csv` | 20,000 | Train KNN + K-Means |
| `datasets/knn_sample.csv` | 40 | Test KNN |
| `datasets/payload_sample.csv` | 24 | Train + test Naive Bayes |
| `datasets/zscore_sample.csv` | 40 | Test Z-Score |
| `datasets/MERGED_CSV/` | 63 files | Full CIC-IoT2023 (future final benchmark) |

List datasets:

```bash
ls -lh datasets/*.csv
wc -l datasets/*.csv
head -3 datasets/knn_sample.csv
head -3 datasets/payload_sample.csv
head -3 datasets/zscore_sample.csv
```

---

## 10. Full demo script for supervisor (5–10 minutes)

Run in order. **§A needs no root. §B needs sudo.**

### Part A — Evidence (no root) ~2 min

```bash
cd src
./benchmark.sh
cat benchmark_report.txt
python3 -m unittest discover -s tests -v
```

**Say:** *"Three models trained, 21 unit tests pass, metrics are reproducible from one script."*

### Part B — Live attacks (root) ~5 min

Open 2 terminals.

**Terminal A:**

```bash
cd src
sudo python3 main.py
# choose 2 for web dashboard
```

**Terminal B:**

```bash
# ── 1. PORT SCAN (KNN engine) ─────────────────────────────────────────────
# nmap    → network scanner
# -sS     → SYN stealth scan (half-open; fast and common in real attacks)
# -p 1-200 → scan destination ports 1 through 200 on the victim
sudo nmap -sS -p 1-200 <VICTIM_IP>

# ── 2. MAXIMUM PACKET FLOOD (Z-Score engine) — supervisor main demo ─────────
# Wait ~10 sec after MANTIS starts so baseline is learned, then run:
#
# sudo       → send raw packets
# hping3     → packet generator
# -S         → TCP SYN flag
# --flood    → send at MAXIMUM speed (no delay between packets)
# -p 80      → target port 80
# <VICTIM_IP> → machine running MANTIS
sudo hping3 -S --flood -p 80 <VICTIM_IP>
# Stop after ~5 seconds: Ctrl+C

# ── 3. SQL INJECTION (Naive Bayes engine) ─────────────────────────────────
nc -l -p 8085 &    # listen on port 8085 for incoming HTTP-like traffic
curl "http://127.0.0.1:8085/?q=1%20UNION%20SELECT%201,2,3"
# %20 = space; UNION SELECT = SQLi keywords Naive Bayes detects
```

**Say for max flood:** *"Sir, this command sends the maximum packets per second to
the victim IP. MANTIS Z-Score detects the spike when packets-per-second exceeds
3 standard deviations above the baseline."*

**Terminal A:** `Ctrl+C` → open `mantis_report.html`

**Say:** *"Five engines, each detects a different attack type. CPU/RAM stay low."*

---

## 11. Supervisor Q&A — short answers

**How many models did you train?**
> Three offline: KNN, K-Means, Naive Bayes. Plus Z-Score (online) and Bloom Filter (blacklist). Saved in `mantis_brain_*.json`.

**How do you compare models?**
> Labelled test CSV → confusion matrix (TP/FP/FN/TN) → Precision, Recall, F1. Same pipeline for every engine via `./benchmark.sh`.

**Which model is best?**
> No single winner — ensemble design. Best per category: KNN for scans, Naive Bayes for payloads, Z-Score for floods. F1 is the primary metric.

**Why is recall 50% on some engines?**
> Small interim test CSVs (24–40 rows). Z-Score also needs a baseline warm-up. Full CIC-IoT2023 split is planned for final dissertation.

**How is this different from Snort/Wazuh?**
> Zero dependencies, transparent maths, active blocking, runs on ~31 MB RAM. Qualitative comparison in `tools/generate_comparison_chart.py`.

**What command sends maximum packets to test DDoS?**
> `sudo hping3 -S --flood -p 80 <VICTIM_IP>` — `--flood` means no delay between
> packets, so hping3 sends at the fastest rate the CPU and network allow. MANTIS
> Z-Score engine counts packets-per-second and alerts when z > 3. Only use on your
> own lab VM.

**What does each part of the flood command mean?**
> `sudo` = root for raw sockets. `hping3` = packet tool. `-S` = SYN TCP flag.
> `--flood` = maximum send rate. `-p 80` = destination port. Last argument =
> victim IP where MANTIS is running.

---

## 12. Troubleshooting

| Problem | Fix |
|---------|-----|
| `bad interpreter: /bin/bash^M` | `sed -i 's/\r$//' src/benchmark.sh src/install.sh` |
| `need sudo for raw sockets` | `sudo python3 main.py` or run `sudo ./install.sh` |
| `AF_PACKET not available` | Container/Windows — train/eval still work; live sensor needs Linux VM |
| No DDoS alert | Let MANTIS baseline ~10 s before flooding; use `sudo hping3 -S --flood -p 80 <VICTIM_IP>` |
| `hping3: command not found` | `sudo apt install hping3` (Debian/Kali/Ubuntu) |
| Dashboard empty | Check `--remote` IP and UDP port 9999 |
| `missing dataset` | Ensure `datasets/cic_iot2023.csv` and sample CSVs exist |
| iptables permission denied | Need real VM with `CAP_NET_ADMIN`, not restricted container |

More help: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 13. All project docs

| File | Purpose |
|------|---------|
| **LIVE_DEMO.md** | This file — all live commands |
| [HOW_TO_RUN.md](HOW_TO_RUN.md) | Install and run modes |
| [TEST_GUIDE.md](TEST_GUIDE.md) | Attack test cases |
| [SUPERVISOR_DEMO_GUIDE.md](SUPERVISOR_DEMO_GUIDE.md) | Viva talking points |
| [README.md](README.md) | Project overview |

---

*Generated for MANTIS dissertation demo. Run `./benchmark.sh` first, then live attacks. Safe to demo only on your own VMs.*

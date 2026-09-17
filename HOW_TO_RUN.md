# How to Run MANTIS

This guide explains how to start the MANTIS Intrusion Detection System in different modes.

## 🚨 IMPORTANT: First-Time Setup
If you see errors like `'python3\r': No such file`, run this fix command first:
```bash
cd src
sed -i 's/\r$//' *.py install.sh
```
Then install:
```bash
cd src
sudo ./install.sh
```

---

## 1. Local Mode (Standalone)
Best for testing or protecting a single laptop/server.

### Command:
```bash
sudo mantis
```
*(Or without install: `cd src && sudo python3 main.py`)*

### What it does:
1.  Starts the **Sensor** to sniff traffic on your network interface.
2.  Loads any existing pre-trained knowledge (`mantis_brain.json`).
3.  Starts the **Multithreaded Analysis Engine** to detect threats using probability math.
4.  Shows alerts in your **Terminal Dashboard** and logs them to `mantis_logs.csv`.
5.  Saves its new learned state to `mantis_brain.json` upon exit (Ctrl+C).

---

## 2. Distributed Mode (Client-Server)
Best for monitoring multiple machines (Clients) from one central dashboard (Server).

### Step A: Start the Server (Dashboard)
On the machine where you want to **see** the logs (e.g., your Admin Laptop):
```bash
mantis-siem
```
*(Or without install: `cd src && python3 dashboard_ui/siem.py`)*

*Note the IP address of this machine (e.g., `192.168.1.50`).*

### Step B: Start the Sensor (Client)
On the machine you want to **protect** (e.g., the Victim VM):
```bash
sudo mantis --remote 192.168.1.50
```
*(Replace `192.168.1.50` with your Server's actual IP).*

### What it does:
- The Sensor detects threats locally.
- Instead of just printing them, it **sends them over UDP** to your Server.
- The Server displays them in real-time.

---

## 3. Help & Options
See all available options:
```bash
mantis --help
```

### Options:
- `--remote <IP>`: Send logs to a remote server.
- `--port <PORT>`: Change UDP port (Default: 9999).

---

## 4. Training Engines from Your Own Data

MANTIS engines can be retrained from a labelled dataset before going
live. The trainer writes `data/mantis_brain_<timestamp>.json` and the
live sensor auto-loads the newest brain on startup.

### From a CSV (KNN)
```bash
mantis-train --knn-csv ../datasets/knn_sample.csv
```
Required CSV columns: `unique_ports,packet_count,label`.

### From a CSV (Naive Bayes payload)
```bash
mantis-train --payload-csv ../datasets/payload_sample.csv
```
Required columns: `payload,label`.

### From the CIC-IoT2023 benchmark
```bash
mantis-train --cic-iot2023 ../datasets/cic_iot2023.csv
```

### Combined JSON dataset
```bash
mantis-train --json my_dataset.json
```

After training, simply run the sensor — it loads the new brain
automatically:
```bash
sudo mantis
```

---

## 5. Evaluating Accuracy

```bash
mantis-eval \
    --knn-csv ../datasets/knn_sample.csv \
    --payload-csv ../datasets/payload_sample.csv \
    --zscore-csv ../datasets/zscore_sample.csv
```

Outputs:

- `evaluation_results.txt` — human-readable confusion matrices and
  Precision / Recall / F1 / Accuracy per engine.
- `evaluation_results.json` — machine-readable for plots and the
  dissertation appendix.

---

## 6. Running the Unit Tests (V-Model)

```bash
cd src
python3 -m unittest discover -s tests -v
```

This validates each engine's mathematics in isolation (no root, no raw
sockets, no network access required).

---

## 7. Cross-Distribution Notes

The installer (`src/install.sh`) auto-detects your distribution and
uses the right package manager (`apt`, `dnf`, `pacman`, `zypper`, `apk`).
It also calls `setcap cap_net_raw,cap_net_admin=eip` on your Python
interpreter so MANTIS can capture packets **without sudo** after
installation. If `setcap` is unavailable on your system (some distros
ship Python as a symlink), simply prefix commands with `sudo`.

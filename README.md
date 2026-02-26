# MANTIS (Minimalist Alert Network for Threat Intelligence System)

A Host-Based Intrusion Detection System (HIDS) built from First Principles.
Designed for minimal resource usage, zero external dependencies, and maximum auditability.

**Features:**
- **Zero-Dependency**: Uses only Python 3 Standard Library.
- **Auditable**: <250 lines of core logic.
- [x] **5-Engine Advanced Detection**:
    1.  **Statistical**: Z-Score (DDoS Detection).
    2.  **Behavioral**: KNN (Port Scan / Scan Ratios).
    3.  **Unsupervised**: K-Means Clustering (Anomaly Grouping).
    4.  **Probabilistic**: Naive Bayes (Payload / SQLi).
    5.  **Reputation**: Bloom Filter (IP Blacklisting).
- [x] **Forensic Reporting**: Generates HTML Incident Reports (`mantis_report.html`) automatically on exit.
- [x] **Distributed Architecture**: Supports sending alerts to a remote dashboard via UDP.

## Requirements
- **Operating System**: Linux (Ubuntu, Kali, Fedora, Debian, CentOS, Arch, Raspbian).
  - *Note: Windows/macOS are NOT supported due to `AF_PACKET` usage.*
- **Language**: Python 3.6+
- **Privileges**: Root/Sudo (Required for Raw Sockets).

## Installation
Clone this repository or copy the `mantis/` folder to your Linux machine.

### Automated Install (Recommended)
```bash
cd src
sudo ./install.sh
```

### Manual Install
No `pip install` required! Just run the python files directly.

## Troubleshooting
Having connectivity issues? Check our [Troubleshooting Guide](TROUBLESHOOTING.md).

## Usage
For detailed instructions, see our **[How to Run Guide](HOW_TO_RUN.md)**.

### 1. Local Mode (Standalone)
Run MANTIS on a single machine. Alerts appear in the console and are logged to `mantis_logs.csv`.

```bash
cd src
sudo python3 main.py
```

### 2. Enterprise SIEM Mode (Web Dashboard)
Run the central dashboard on one machine (e.g., Ubuntu). Note: You can also just select the "Web Dashboard" option when running `main.py`.

```bash
cd src
python3 dashboard_ui/siem.py
```
*   **Web Interface**: Open `http://localhost:8080` in your browser.
*   **UDP Listener**: Listening on Port 9999.

**Connect Sensors:**
On your other machines (sensors), run:
```bash
cd src
sudo python3 main.py --remote <SIEM_IP> --port 9999
```

### 3. Help
```bash
cd src
sudo python3 main.py --help
```

## Quick Start (GitHub Users)
If you clone this repo:
```bash
git clone https://github.com/YOUR_USERNAME/MANTIS.git
cd MANTIS/src
sudo chmod +x main.py
sudo ./main.py
```

### Using Over the Internet (World Wide Web)
If you want to send logs to a Dashboard on a **Different Network** (e.g., Friend in another country):
1.  **On Dashboard Machine**: Find your Public IP (`curl ifconfig.me`).
2.  **On Router**: Forward **UDP Port 9999** to your Dashboard Machine's local IP.
3.  **On Friend's Machine**: Run:
    ```bash
    sudo mantis --remote YOUR_PUBLIC_IP
    ```

## Logs & Evidence
All alerts are automatically saved to `mantis_logs.csv` in the current directory for post-incident analysis.

## Limitations & Future Work
**Important for Defense/Viva:**
1.  **HTTPS Visibility:** MANTIS operates at the Network Layer (Layer 3/4). It cannot decrypt HTTPS traffic (Layer 7). Therefore, the **Payload Engine** (Naive Bayes) only works on unencrypted HTTP or if SSL Termination is done upstream.
    *   *Future Work:* Integrate with a transparent proxy (MitM) or read web server logs directly.
2.  **Performance:** As a Python-based user-space tool, MANTIS is slower than kernel-space tools like eBPF or C-based engines (Snort).
    *   *Future Work:* Rewrite the core packet capture loop in C or Rust.
3.  **Spoofing:** MANTIS relies on IP headers, which can be spoofed (UDP).

## License
MIT License. Free to use and modify.

# How to Run MANTIS

This guide explains how to start the MANTIS Intrusion Detection System in different modes.

## 🚨 IMPORTANT: First-Time Setup
If you see errors like `'python3\r': No such file`, run this fix command first:
```bash
sed -i 's/\r$//' *.py install.sh
```
Then install:
```bash
sudo ./install.sh
```

---

## 1. Local Mode (Standalone)
Best for testing or protecting a single laptop/server.

### Command:
```bash
sudo mantis
```
*(Or without install: `sudo python3 main.py`)*

### What it does:
1.  Starts the **Sensor** to sniff traffic on your network interface.
2.  Starts the **Analysis Engine** to detect threats.
3.  Shows alerts in your **Terminal Dashboard**.
4.  Logs alerts to `mantis_logs.csv` in the current folder.

---

## 2. Distributed Mode (Client-Server)
Best for monitoring multiple machines (Clients) from one central dashboard (Server).

### Step A: Start the Server (Dashboard)
On the machine where you want to **see** the logs (e.g., your Admin Laptop):
```bash
mantis-server
```
*(Or without install: `python3 log_server.py`)*

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

# MANTIS Troubleshooting Guide

Encountering issues with MANTIS? Use this guide to diagnose and fix common problems.

## 1. Remote Logging Not Working ("Why not working remotely?")
If the sensor (client) cannot send alerts to the dashboard (server), check these common culprits:

### A. Firewall Issues (Most Common)
By default, Linux firewalls (UFW/IPTables) block incoming UDP traffic on custom ports like 9999.

**Solution (On Server Machine):**
Allow UDP traffic on port 9999:
```bash
sudo ufw allow 9999/udp
```
Or check if it's open:
```bash
sudo ufw status
```

### B. Wrong IP Address
Ensure the sensor is pointing to the **Server's IP Address**, not `localhost` or `127.0.0.1`.

**Check Server IP:**
Run `ifconfig` or `ip a` on the Server machine. Look for `inet 192.168.x.x`.

**Run Sensor correctly:**
```bash
# Replace 192.168.1.50 with your ACTUAL Server IP
sudo mantis --remote 192.168.1.50
```

### C. Server Must Start FIRST
The UDP listener (server) must be running **before** the sensor sends data, or packets will be dropped.

**Order of Operations:**
1.  **Server Machine:** `sudo python3 log_server.py` (or `mantis-server`)
2.  **Client Machine:** `sudo python3 main.py --remote <SERVER_IP>`

---

## 2. "Permission Denied" Errors
MANTIS uses **Raw Sockets** to sniff packets. This requires Root privileges.

**Symptom:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Solution:**
Always run with `sudo`:
```bash
sudo python3 main.py
```

---

## 3. "Module Not Found" Errors
MANTIS relies on standard libraries, but ensures you are running **Python 3**.

**Symptom:**
```
ImportError: No module named 'struct'
```

**Solution:**
Ensure you are using `python3`, not `python` (which might be Python 2.x on older systems):
```bash
python3 --version
```

---

## 4. Installation Issues
If `install.sh` fails:

1.  **Make it executable:**
    ```bash
    chmod +x install.sh
    ```
2.  **Run as Root:**
    ```bash
    sudo ./install.sh
    ```
3.  **Manual Install:**
    If the script fails, just run the python files directly from the download folder. The script is optional.

---

## 5. "python3\r: No such file or directory"
**Symptom:**
You see an error like:
```
/usr/bin/env: 'python3\r': No such file or directory
```
**Cause:**
This is the **"Windows Curse"**. You copied files from Windows to Linux, and Windows adds invisible `\r` characters to the end of lines. Linux assumes `python3\r` is the program name, which doesn't exist.

**Solution:**
Run this command to remove the invisible characters:
```bash
sudo sed -i 's/\r$//' /opt/mantis/*.py
```
If running from the local folder:
```bash
sed -i 's/\r$//' *.py
```

# MANTIS Installation Guide

Since MANTIS is a **Zero-Dependency** tool, it doesn't need `pip install`.
However, you can "install" it as a system command for convenience.

## Prerequisites
- **OS**: Linux (Ubuntu, Kali, Fedora, Debian, etc.)
- **Python**: Version 3.6+
- **Root Access**: Required for raw sockets.

## Step 1: Download & Prepare
1.  Copy the `mantis/` folder to your Linux machine (e.g., to your Home directory).
2.  Open a terminal inside the folder.

## Step 2: Install to System (Optional)
To run MANTIS from anywhere (like a real tool), follow these steps:

1.  **Move to /opt**:
    ```bash
    sudo mv mantis /opt/mantis
    ```

2.  **Make Executable**:
    ```bash
    sudo chmod +x /opt/mantis/main.py
    ```

3.  **Create Symlink**:
    ```bash
    sudo ln -s /opt/mantis/main.py /usr/bin/mantis
    ```

## Step 3: Verify Installation
Now you can run MANTIS from any directory!

```bash
# Check Help
mantis --help

# Run in Local Mode
sudo mantis

# Run in Distributed Mode
sudo mantis --remote 192.168.1.50
```

## Uninstallation
To remove MANTIS:
```bash
sudo rm /usr/bin/mantis
sudo rm -rf /opt/mantis
```

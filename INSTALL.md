# MANTIS Installation Guide

MANTIS uses no third-party Python packages in its runtime detection path, so
it does not require `pip install`. The installer can install the Linux
`iptables` and `libcap` operating-system packages when needed.

## Prerequisites
- **OS**: Linux (Ubuntu, Kali, Fedora, Debian, etc.)
- **Python**: Version 3.6+
- **Root Access**: Required for installation and as a fallback for raw sockets.

## Step 1: Download & Prepare
1.  Copy the `mantis/` folder to your Linux machine (e.g., to your Home directory).
2.  Open a terminal inside the `mantis/src/` folder.

## Step 2: Install to System

Run the maintained installer from `mantis/src`:

```bash
sudo ./install.sh
```

It copies the application to `/opt/mantis`, sets executable permissions,
attempts to grant Linux packet-capture capabilities and creates command links.
Compatibility links in `/usr/bin` ensure `sudo mantis` and
`sudo mantis-demo-attacks` work even when sudo omits `/usr/local/bin`.

## Step 3: Verify Installation
Now you can run MANTIS from any directory!

```bash
# Check Help
mantis --help

# Run the web sensor
mantis --mode web

# Root fallback
sudo mantis --mode web

# Run in Distributed Mode
sudo mantis --remote 192.168.1.50

# Safe repeatable offline test
mantis-replay --generate ~/mantis-test.pcap
mantis-replay --pcap ~/mantis-test.pcap

# Live localhost demonstration (start MANTIS first)
sudo mantis-demo-attacks lo 5
```

## Uninstallation
To remove MANTIS from your system completely, you can use the provided uninstall script:
```bash
cd src
sudo ./uninstall.sh
```

The uninstaller removes command links from both `/usr/local/bin` and
`/usr/bin`, then removes `/opt/mantis`.

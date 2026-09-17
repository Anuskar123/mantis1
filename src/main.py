#!/usr/bin/env python3
import argparse
import os
import queue
import socket
import sys
import threading
import time

import dashboard_ui.dashboard as dashboard
import sensor_node.sensor as sensor
from utils.config import CONFIG


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="mantis",
        description="MANTIS - Minimalist Alert Network for Threat "
                    "Intelligence System",
        epilog="Active defence is OFF unless --block is given (NFR-3).")

    p.add_argument("--remote", default=None,
                   help="dashboard server IP (distributed mode)")
    p.add_argument("--port", type=int, default=None,
                   help="udp telemetry port (default 9999)")
    p.add_argument("--mode", choices=["cli", "web"], default=None,
                   help="skip the interactive prompt and pick a UI")
    p.add_argument("--config", default=None,
                   help="json config file to load")

    # --- detection tuning ---
    p.add_argument("--zscore-threshold", type=float, default=None,
                   help="z-score alert threshold (default 3.0)")
    p.add_argument("--zscore-window", type=int, default=None,
                   help="rolling baseline window in seconds (default 30)")
    p.add_argument("--ddos-min-pps", type=int, default=None,
                   help="minimum packet rate eligible for DDoS (default 500)")
    p.add_argument("--ddos-consecutive",
                   dest="ddos_consecutive_intervals",
                   type=int, default=None,
                   help="consecutive anomalous seconds required (default 3)")
    p.add_argument("--knn-k", type=int, default=None, help="KNN neighbours")
    p.add_argument("--alert-dedup-seconds", type=float, default=None,
                   help="suppress identical alerts for this long (default 5)")
    p.add_argument("--source-attribution-min-share", type=float, default=None,
                   help="minimum dominant-source traffic share required to "
                        "attribute interval alerts (default 0.50)")

    # --- response (NFR-3: opt-in) ---
    p.add_argument("--block", dest="block_enabled", action="store_true",
                   default=None,
                   help="ENABLE iptables blocking (off by default)")
    p.add_argument("--block-on", default=None,
                   help="comma list of kinds that may trigger a block "
                        "(payload,blacklist,ddos,scan)")

    # --- privacy (NFR-3 / GDPR) ---
    p.add_argument("--no-privacy", dest="privacy_mode", action="store_false",
                   default=None, help="disable PII redaction in logs")
    p.add_argument("--anonymise-ips", dest="anonymise_ips",
                   action="store_true", default=None,
                   help="mask the last octet of IPs in persisted logs")
    p.add_argument("--payload-excerpt-bytes", type=int, default=None,
                   help="payload excerpt limit in bytes (default 64)")

    # --- forensics ---
    p.add_argument("--pcap-file", default=None,
                   help="write a live libpcap capture (opens in Wireshark)")
    p.add_argument("--pcap-snaplen", type=int, default=None,
                   help="bytes captured per frame (default 96, headers only)")
    p.add_argument("--blacklist-file", default=None,
                   help="threat-intel IP feed, one indicator per line")
    p.add_argument("--log-file", default=None, help="csv audit log path")
    p.add_argument("--packet-buffer", type=int, default=None,
                   help="in-memory packet ring buffer size (default 5000)")

    return p.parse_args(argv)


BANNER = r"""
    __  ___ ___   _   _  _____  ___   ____
   /  |/  //   | / | / /|_   _|/ _ \ / ___|
  / /|_/ // /| |/  |/ /   | | | | | |\___ \
 / /  / // ___ / /|  /    | | | |_| | ___) |
/_/  /_//_/  |_/_/ |_/    |_|  \___/ |____/
    Minimalist Alert Network for Threat Intelligence System
"""


def has_raw_capture_access():
    """Return True when this process can open the Linux capture socket.

    Root is not the only valid case: install.sh can grant CAP_NET_RAW to the
    Python interpreter, so a non-root `mantis` process may be fully authorised.
    Probing the actual socket keeps both `mantis` and `sudo mantis` honest.
    """
    if not hasattr(socket, "AF_PACKET"):
        return False
    probe = None
    exit_code = 0
    try:
        probe = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return True
    except (PermissionError, OSError):
        return False
    finally:
        if probe is not None:
            probe.close()


def main(argv=None):
    args = parse_args(argv)
    if not has_raw_capture_access():
        print("[!] raw packet capture is unavailable")
        print("    run with sudo, or install capabilities using sudo ./install.sh")
        print("    offline alternative:")
        print("      python3 replay.py --generate demo.pcap")
        print("      python3 replay.py --pcap demo.pcap")
        return 1
    print(BANNER)

    # config precedence: defaults -> file -> environment -> cli flags
    if args.config:
        CONFIG.load_file(args.config)
    CONFIG.load_env()

    if args.port is not None:
        CONFIG.udp_port = args.port
    if args.block_on:
        CONFIG.block_on = [k.strip() for k in args.block_on.split(",")
                           if k.strip()]
    for key in ("zscore_threshold", "zscore_window", "ddos_min_pps",
                "ddos_consecutive_intervals", "knn_k", "block_enabled",
                "alert_dedup_seconds",
                "source_attribution_min_share",
                "privacy_mode", "anonymise_ips", "payload_excerpt_bytes",
                "pcap_file", "pcap_snaplen", "blacklist_file", "log_file",
                "packet_buffer"):
        value = getattr(args, key, None)
        if value is not None:
            setattr(CONFIG, key, value)

    if args.mode:
        op_mode = args.mode.upper()
    else:
        print("Mode: 1) CLI dashboard   2) Web dashboard (port %d)"
              % CONFIG.http_port)
        choice = input("Choice [1/2] (default 1): ").strip()
        op_mode = "WEB" if choice == "2" else "CLI"

    if CONFIG.block_enabled:
        print("[!] ACTIVE DEFENCE ENABLED - iptables DROP rules will be "
              "inserted for: %s" % ", ".join(CONFIG.block_on))
    else:
        print("[*] active defence disabled (pass --block to enable)")

    stats_q = queue.Queue()
    alert_q = queue.Queue()

    ui = None
    forward_alerts = False

    if op_mode == "CLI":
        ui = dashboard.Dashboard()
        if args.remote:
            CONFIG.udp_host = args.remote
            forward_alerts = True
            print("[*] distributed mode -> %s:%d"
                  % (CONFIG.udp_host, CONFIG.udp_port))
    else:
        import dashboard_ui.siem as siem
        threading.Thread(target=siem.start_siem, daemon=True).start()
        print("[*] web dashboard: http://127.0.0.1:%d" % CONFIG.http_port)
        CONFIG.udp_host = args.remote or "127.0.0.1"
        forward_alerts = True
        time.sleep(1)

    # Keep a concrete sensor reference so the main thread can request an
    # orderly shutdown.  The previous daemon-only launch let Python terminate
    # before the sensor exported its brain, closed the PCAP, or wrote the
    # session report when Ctrl+C was received by this thread.
    node = sensor.SensorNode(
        stats_queue=stats_q,
        alert_queue=alert_q,
        config=CONFIG,
        forward_alerts=forward_alerts,
    )
    sensor_thread = threading.Thread(target=node.start, daemon=False)
    sensor_thread.start()

    try:
        while sensor_thread.is_alive():
            latest = None
            while not stats_q.empty():
                try:
                    latest = stats_q.get_nowait()
                except queue.Empty:
                    break
            if latest and ui:
                ui.update_stats(latest["pps"], latest["mean"],
                                latest["z_score"],
                                latest.get("ddos_candidate", False),
                                latest.get("ddos_active", False))

            while not alert_q.empty():
                try:
                    msg = alert_q.get_nowait()
                except queue.Empty:
                    break
                if ui:
                    ui.add_alert(msg)

            if ui:
                ui.refresh()

            # 10 small sleeps so ctrl+c reacts quickly
            for _ in range(10):
                time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[!] shutting down")
        node.shutdown()
    finally:
        if sensor_thread.is_alive():
            node.shutdown()
        sensor_thread.join(timeout=5.0)
        if sensor_thread.is_alive():
            print("[!] sensor thread did not stop within 5 seconds")
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

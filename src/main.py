#!/usr/bin/env python3
import threading
import queue
import time
import sys
import os
import argparse # Phase 9: CLI Argument Parsing

# Import Modules
import sensor_node.sensor as sensor
import dashboard_ui.dashboard as dashboard
import utils.logger as logger # Phase 6 & 8: Logging

def parse_arguments():
    parser = argparse.ArgumentParser(description="MANTIS: Minimalist Alert Network for Threat Intelligence System")
    parser.add_argument("--remote", help="IP Address of the Dashboard Server (for Distributed Mode)", default=None)
    parser.add_argument("--port", help="UDP Port for Remote Logging (Default: 9999)", type=int, default=9999)
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    print(r"""
    __  ___ ___   _   _  _____  ___   ____ 
   /  |/  //   | / | / /|_   _|/ _ \ / ___|
  / /|_/ // /| |/  |/ /   | | | | | |\___ \
 / /  / // ___ / /|  /    | | | |_| | ___) |
/_/  /_//_/  |_/_/ |_/    |_|  \___/ |____/
    Minimalist Alert Network for Threat Intelligence System
""")
    print("Please select your operational mode:")
    print("1) CLI Dashboard (Standard Terminal View)")
    print("2) Web Dashboard (Instana/Motadata Style UI on Port 8080)")
    
    choice = input("Enter choice [1/2] (Default: 1): ").strip()
    op_mode = "WEB" if choice == "2" else "CLI"

    # 1. Setup Queues
    # These shared queues allow the Sensor Thread to talk to the Main Dashboard Thread
    stats_queue = queue.Queue()
    alert_queue = queue.Queue()
    
    # 2. Start Sensor in Background Thread
    # 'daemon=True' means this thread dies automatically when the main program exits
    sensor_thread = threading.Thread(
        target=sensor.start_sensor,
        args=(stats_queue, alert_queue),
        daemon=True
    )
    sensor_thread.start()
    
    # 3. Initialize Dashboard & Logger
    ui = None
    if op_mode == "CLI":
        ui = dashboard.Dashboard()
    else:
        # Start SIEM locally in a thread
        import dashboard_ui.siem as siem
        siem_thread = threading.Thread(target=siem.start_siem, daemon=True)
        siem_thread.start()
        print("[*] Web Dashboard started in background.")
    
    # Local CSV Logger (Always active for evidence)
    local_logger = logger.Logger()
    
    # Remote Logger (Optional) or Local Web Mode
    remote_logger = None
    if op_mode == "WEB":
        print(f"[*] Sending local sensor logs to Web Dashboard on UDP localhost:9999")
        remote_logger = logger.UDPSender("127.0.0.1", 9999)
        # We also need a way to send raw packets if they want the Wireshark view, but we'll integrate that into SIEM later.
    elif args.remote:
        print(f"[*] Distributed Mode Enabled. Sending logs to {args.remote}:{args.port}")
        remote_logger = logger.UDPSender(args.remote, args.port)
        time.sleep(2) # Give user time to read
    
    # 4. Main Event Loop
    try:
        while True:
            # A. Process Stats (Non-blocking)
            try:
                # We consume all available stats updates, but only keep the latest
                latest_stats = None
                while not stats_queue.empty():
                    latest_stats = stats_queue.get_nowait()
                
                if latest_stats:
                    if ui:
                        ui.update_stats(
                            latest_stats['pps'],
                            latest_stats['mean'],
                            latest_stats['z_score']
                        )
                    # For Web Dashboard, we'll send stats directly or let it pull from ACTIVE_SENSORS
            except queue.Empty:
                pass
                
            # B. Process Alerts (Non-blocking)
            try:
                while not alert_queue.empty():
                    alert_msg = alert_queue.get_nowait()
                    if ui:
                        ui.add_alert(alert_msg)
                    
                    # Log Evidence to Local CSV (For Dissertation)
                    local_logger.log_alert(alert_msg)
                    
                    # Send to Remote Dashboard (if configured)
                    if remote_logger:
                        remote_logger.send_log(alert_msg)
                    
            except queue.Empty:
                pass
            
            # C. Refresh UI (only if CLI)
            if ui:
                ui.refresh()
            
            # D. Wait 1 second (Refresh Rate)
            # Use small sleeps to keep UI responsive to Ctrl+C
            for _ in range(10):
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        print("\n[!] Shutting down MANTIS...")
        sys.exit(0)

if __name__ == "__main__":
    # Check for Root (Required for Sensor)
    if os.name != 'nt' and os.geteuid() != 0:
        print("[!] Error: This script must be run as root (sudo).")
        sys.exit(1)
        
    main()

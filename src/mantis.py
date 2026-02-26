#!/usr/bin/env python3
import sys
import subprocess
import time

def print_banner():
    print("==================================================")
    print("  M.A.N.T.I.S. (Minimalist Alert Network for Threat Intelligence System) ")
    print("==================================================")

def main():
    print_banner()
    print("[*] MANTIS Setup Wrapper")
    
    choice = input("[?] Run MANTIS in (L)ocal standalone mode or (R)emote mode? [L/R]: ").strip().upper()
    
    if choice == 'R':
        siem_ip = input("[?] Enter the central SIEM Server IP address (e.g. 192.168.1.50): ").strip()
        print(f"[*] Starting MANTIS in Remote Mode. Logs will be forwarded to {siem_ip}:9999")
        # In the future (Phase 5), we will pass the siem_ip to sensor.py
        # subprocess.Popen(["sudo", "python3", "sensor_node/sensor.py", "--siem", siem_ip])
        print("[!] Remote Mode initialization complete! (Engines pending Phase 1-4 completion)")
        
    elif choice == 'L':
        print("[*] Starting MANTIS in Local Mode...")
        
        # 1. Start the SIEM Dashboard
        try:
            print("[*] Launching SIEM Dashboard...")
            siem_process = subprocess.Popen(["python3", "dashboard_ui/siem.py"])
            time.sleep(2) # Give it a moment to boot
            
            # 2. Start the Sensor (Phase 1)
            print("[*] Launching MANTIS Sensor (Requires Root)...")
            sensor_process = subprocess.Popen(["sudo", "python3", "sensor_node/sensor.py"])
            
            print("[+] MANTIS is currently running locally! Press Ctrl+C to terminate.")
            
            # Keep alive until user stops
            siem_process.wait()
            sensor_process.wait()
            
        except KeyboardInterrupt:
            print("\n[!] Shutting down MANTIS systems...")
            siem_process.terminate()
            if 'sensor_process' in locals():
                subprocess.Popen(["sudo", "pkill", "-f", "sensor_node/sensor.py"])
            sys.exit(0)
    else:
        print("[!] Invalid choice. Please run again and select L or R.")

if __name__ == "__main__":
    main()

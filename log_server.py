#!/usr/bin/env python3
import socket
import time

# MANTIS Phase 8: Central Log Server (Distributed Dashboard)

def start_server(port=9999):
    """
    Listens for UDP alerts from remote MANTIS sensors.
    """
    # 0.0.0.0 means listen on all interfaces
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        server_sock.bind(('0.0.0.0', port))
        print(f"[*] MANTIS Central Log Serve Running on UDP Port {port}")
        print("[*] Waiting for alerts from Fedora Sensor...")
        print("-------------------------------------------------------")
        
        while True:
            # Receive data (max 1024 bytes)
            data, addr = server_sock.recvfrom(1024)
            message = data.decode('utf-8')
            
            # Print Alert with nicer formatting
            print(f"[REMOTE ALERT from {addr[0]}] {message}")
            
    except PermissionError:
        print(f"[!] Error: Cannot bind to port {port}. Try sudo or a port > 1024.")
    except KeyboardInterrupt:
        print("\n[!] Stopping Log Server.")
    except Exception as e:
        print(f"[!] Error: {e}")
        
if __name__ == "__main__":
    start_server()

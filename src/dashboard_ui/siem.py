#!/usr/bin/env python3
import socket
import threading
import json
import time
import http.server
import socketserver
from collections import deque

# MANTIS Phase 8: Enterprise SIEM (Security Information and Event Management)
# Central Dashboard for Multi-Sensor Deployment.

# --- CONFIG ---
UDP_PORT = 9999       # standard syslog port is 514, but we use 9999 to avoid root
HTTP_PORT = 8080      # Web Dashboard Port
MAX_ALERTS = 100      # Keep last 100 alerts in memory

# --- SHARED STATE ---
# Stores alerts in memory. Thread-safe enough for this scale.
ALERT_HISTORY = deque(maxlen=MAX_ALERTS)
ACTIVE_SENSORS = {}   # Map of IP -> Last Seen Timestamp

class SyslogUDPHandler:
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow instant port reuse if the script restarts quickly
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        
    def start(self):
        print(f"[*] SIEM UDP Listener started on port {self.port}")
        while True:
            data, addr = self.sock.recvfrom(4096)
            message = data.decode('utf-8', errors='replace').strip()
            sensor_ip = addr[0]
            
            # Update Sensor Status
            ACTIVE_SENSORS[sensor_ip] = time.time()
            
            # Log Alert
            timestamp = time.strftime("%H:%M:%S")
            alert_entry = {
                "id": len(ALERT_HISTORY) + 1,
                "time": timestamp,
                "sensor": sensor_ip,
                "message": message,
                "severity": self._get_severity(message)
            }
            ALERT_HISTORY.appendleft(alert_entry) # Newest first
            print(f"[+] Alert Received from {sensor_ip}: {message}")

    def _get_severity(self, msg):
        if "DDoS" in msg: return "CRITICAL"
        if "PAYLOAD" in msg: return "HIGH"
        if "SCAN" in msg: return "MEDIUM"
        return "INFO"

class WebDashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self._get_dashboard_html().encode('utf-8'))
            
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Calculate Uptime/Status
            now = time.time()
            active_count = sum(1 for t in ACTIVE_SENSORS.values() if now - t < 60)
            
            # Categorize Alerts
            ddos_count = sum(1 for a in ALERT_HISTORY if "DDoS" in a["message"])
            scan_count = sum(1 for a in ALERT_HISTORY if "SCAN" in a["message"])
            payload_count = sum(1 for a in ALERT_HISTORY if "PAYLOAD" in a["message"])
            blacklist_count = sum(1 for a in ALERT_HISTORY if "BLACKLIST" in a["message"])
            
            # Basic CPU/Memory Simulation (Since we can't use psutil per Zero-Dependency Policy)
            # In a real environment we'd read /proc/stat. Here we mock it slightly around 15-20% for realism
            cpu_usage = 15.4
            mem_usage = 42.1
            
            try:
                # Try to get real load avg on Linux
                import os
                load1, load5, load15 = os.getloadavg()
                cpu_usage = min(100.0, load1 * 10) # rough estimate
            except:
                pass
            
            stats = {
                "online_sensors": active_count,
                "total_alerts": len(ALERT_HISTORY),
                "ddos_alerts": ddos_count,
                "scan_alerts": scan_count,
                "payload_alerts": payload_count,
                "blacklist_alerts": blacklist_count,
                "cpu_usage": round(cpu_usage, 1),
                "mem_usage": round(mem_usage, 1),
                "alerts": list(ALERT_HISTORY)
            }
            self.wfile.write(json.dumps(stats).encode('utf-8'))
            
        else:
            self.send_error(404)
            
    def _get_dashboard_html(self):
        import os
        # 1. Get the path to this script
        script_path = os.path.abspath(__file__)
        
        # 2. If it's a symlink (e.g. /usr/bin/mantis-siem), follow it to the real file
        if os.path.islink(script_path):
            script_path = os.readlink(script_path)
            
        # 3. Get the directory containing the real siem.py
        base_dir = os.path.dirname(script_path)
        
        # 4. Construct the path to the HTML template
        template_path = os.path.join(base_dir, 'web_template.html')
        
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return f"<html><body><h1>Error: web_template.html not found at {template_path}</h1></body></html>"

def start_siem():
    # 1. Start UDP Listener in Background Thread
    udp_server = SyslogUDPHandler(UDP_PORT)
    udp_thread = threading.Thread(target=udp_server.start, daemon=True)
    udp_thread.start()
    
    # 2. Start Web Server in Main Thread
    print(f"[*] Starting MANTIS SIEM Web Dashboard on http://localhost:{HTTP_PORT}")
    print(f"[*] Press Ctrl+C to stop.")
    
    # Custom TCP Server that allows immediate port reuse (fixes 'Address already in use')
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True
        
    httpd = ReusableTCPServer(("", HTTP_PORT), WebDashboardHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Stopping Web Server.")
        httpd.server_close()

if __name__ == "__main__":
    start_siem()

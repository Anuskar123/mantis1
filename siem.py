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
        self.sock.bind(('0.0.0.0', self.port))
        
    def start(self):
        print(f"[*] SIEM UDP Listener started on port {self.port}")
        while True:
            data, addr = self.sock.recvfrom(4096)
            message = data.decode('utf-8').strip()
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
            
            # Calculate Upsptime/Status
            now = time.time()
            active_count = sum(1 for t in ACTIVE_SENSORS.values() if now - t < 60)
            
            stats = {
                "online_sensors": active_count,
                "total_alerts": len(ALERT_HISTORY),
                "alerts": list(ALERT_HISTORY)
            }
            self.wfile.write(json.dumps(stats).encode('utf-8'))
            
        else:
            self.send_error(404)
            
    def _get_dashboard_html(self):
        return """
<!DOCTYPE html>
<html>
<head>
    <title>MANTIS SIEM Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0f111a; color: #e0e6ed; margin: 0; display: flex; flex-direction: column; height: 100vh; }
        header { background: #1a1c29; padding: 20px; border-bottom: 2px solid #00ff9d; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; color: #00ff9d; letter-spacing: 2px; }
        .grid { display: grid; grid-template-columns: 300px 1fr; gap: 20px; padding: 20px; flex: 1; }
        .card { background: #1a1c29; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.5); }
        .stat-box { text-align: center; margin-bottom: 20px; }
        .stat-val { font-size: 36px; font-weight: bold; color: #fff; }
        .stat-label { color: #888; font-size: 14px; text-transform: uppercase; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { text-align: left; color: #888; padding: 10px; border-bottom: 1px solid #333; }
        td { padding: 12px 10px; border-bottom: 1px solid #2a2d3e; font-family: monospace; }
        tr:hover { background: #252836; }
        
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .CRITICAL { background: #ff4444; color: white; }
        .HIGH { background: #ff8800; color: white; }
        .MEDIUM { background: #ffbb33; color: black; }
        .INFO { background: #33b5e5; color: white; }
        
        .sensor-dot { height: 10px; width: 10px; background-color: #00ff9d; border-radius: 50%; display: inline-block; margin-right: 5px; }
        .sensor-offline { background-color: #555; }
        
        /* Scanline Animation */
        .scanline { width: 100%; height: 2px; background: rgba(0,255,157,0.3); position: fixed; top: 0; animation: scan 3s linear infinite; pointer-events: none; }
        @keyframes scan { 0% { top: 0%; } 100% { top: 100%; } }
    </style>
    <script>
        async function fetchStats() {
            try {
                let response = await fetch('/api/stats');
                let data = await response.json();
                
                // Update Counters
                document.getElementById('sensorRequestVal').innerText = data.online_sensors;
                document.getElementById('totalAlertsVal').innerText = data.total_alerts;
                
                // Update Table
                let tbody = document.getElementById('alertTableBody');
                tbody.innerHTML = ''; // Clear
                
                data.alerts.forEach(alert => {
                    let row = `<tr>
                        <td><span class="badge ${alert.severity}">${alert.severity}</span></td>
                        <td>${alert.time}</td>
                        <td>${alert.sensor}</td>
                        <td style="color: #ccc;">${alert.message}</td>
                    </tr>`;
                    tbody.innerHTML += row;
                });
                
            } catch (e) { console.error(e); }
        }
        
        // Refresh every 2 seconds
        setInterval(fetchStats, 2000);
        window.onload = fetchStats;
    </script>
</head>
<body>
    <div class="scanline"></div>
    <header>
        <h1>M.A.N.T.I.S. <span style="font-size: 12px; opacity: 0.7;">ENTERPRISE SIEM</span></h1>
        <div style="font-family: monospace;">STATUS: <span style="color: #00ff9d;">OPERATIONAL</span></div>
    </header>
    
    <div class="grid">
        <!-- Sidebar Stats -->
        <div class="column">
            <div class="card stat-box">
                <div class="stat-val" id="sensorRequestVal">0</div>
                <div class="stat-label">Active Sensors</div>
            </div>
            <div class="card stat-box">
                <div class="stat-val" id="totalAlertsVal">0</div>
                <div class="stat-label">Total Threats Detected</div>
            </div>
            <div class="card">
                <h3 style="color: #888; border-bottom: 1px solid #333; padding-bottom: 10px;">SYSTEM HEALTH</h3>
                <div style="margin-top: 10px; font-size: 14px;">
                    <div><span class="sensor-dot"></span> Cluster Main (This Node)</div>
                    <div style="margin-top: 5px;"><span class="sensor-dot"></span> Database (SQLite Memory)</div>
                    <div style="margin-top: 5px;"><span class="sensor-dot"></span> Web Uplink (Port 8080)</div>
                </div>
            </div>
        </div>
        
        <!-- Main Alert Feed -->
        <div class="card" style="overflow-y: auto;">
            <h2 style="margin-top: 0; color: #fff;">LIVE THREAT FEED</h2>
            <table>
                <thead>
                    <tr>
                        <th width="80">SEV</th>
                        <th width="100">TIME</th>
                        <th width="120">SENSOR IP</th>
                        <th>MESSAGE PAYLOAD</th>
                    </tr>
                </thead>
                <tbody id="alertTableBody">
                    <!-- Populated via JS -->
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
        """

def start_siem():
    # 1. Start UDP Listener in Background Thread
    udp_server = SyslogUDPHandler(UDP_PORT)
    udp_thread = threading.Thread(target=udp_server.start, daemon=True)
    udp_thread.start()
    
    # 2. Start Web Server in Main Thread
    print(f"[*] Starting MANTIS SIEM Web Dashboard on http://localhost:{HTTP_PORT}")
    print(f"[*] Press Ctrl+C to stop.")
    
    httpd = socketserver.TCPServer(("", HTTP_PORT), WebDashboardHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Stopping Web Server.")
        httpd.server_close()

if __name__ == "__main__":
    start_siem()

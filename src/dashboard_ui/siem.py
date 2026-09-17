#!/usr/bin/env python3
import socket
import threading
import json
import os
import sys
import time
import http.server
import socketserver
from collections import deque
from urllib.parse import urlparse, parse_qs

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils.packet_store as packet_store
import utils.pcap as pcap
from utils.config import CONFIG

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
        import re
        legacy_format = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]')

        while True:
            data, addr = self.sock.recvfrom(8192)
            sensor_ip = addr[0]
            raw = data.decode('utf-8', errors='replace').strip()

            # FR-5 sends structured JSON. Fall back to the original bracketed
            # text format so a sensor running older code still reports, and
            # reject anything else - port 9999 is itself a scan target, so
            # arbitrary bytes do arrive here.
            entry = None
            if raw.startswith('{'):
                try:
                    frame = json.loads(raw)
                    if isinstance(frame, dict) and "message" in frame:
                        entry = {
                            "message": frame.get("message", ""),
                            "severity": frame.get(
                                "severity",
                                self._get_severity(frame.get("message", ""))),
                            "src_ip": frame.get("src_ip", ""),
                            "engine": frame.get("engine", ""),
                            "kind": frame.get("kind", ""),
                            "technique_id": frame.get("technique_id", ""),
                            "technique": frame.get("technique", ""),
                            "tactic": frame.get("tactic", ""),
                            "risk_score": frame.get("risk_score", 0),
                            "confidence": frame.get("confidence"),
                            "payload_excerpt": frame.get("payload_excerpt", ""),
                        }
                except ValueError:
                    entry = None

            if entry is None:
                if legacy_format.match(raw):
                    message = raw
                else:
                    message = ("INVALID UDP PAYLOAD (Raw Binary/Port Scan "
                               "detected on SIEM Listener)")
                entry = {
                    "message": message,
                    "severity": self._get_severity(message),
                    "src_ip": "", "engine": "", "kind": "",
                    "technique_id": "", "technique": "", "tactic": "",
                    "risk_score": 0, "confidence": None,
                    "payload_excerpt": "",
                }

            # Update Sensor Status
            ACTIVE_SENSORS[sensor_ip] = time.time()

            entry["id"] = len(ALERT_HISTORY) + 1
            entry["time"] = time.strftime("%H:%M:%S")
            entry["sensor"] = sensor_ip
            ALERT_HISTORY.appendleft(entry)  # Newest first
            print("[+] %s | %s | %s" % (sensor_ip,
                                        entry.get("technique_id") or "-",
                                        entry["message"]))

    def _get_severity(self, msg):
        if "DDoS" in msg: return "CRITICAL"
        if "PAYLOAD" in msg: return "HIGH"
        if "SCAN" in msg: return "MEDIUM"
        return "INFO"


# --- Real host telemetry (Linux /proc, zero dependencies) ---
_LAST_CPU = {"total": 0, "idle": 0}


def read_cpu_percent():
    """CPU utilisation from /proc/stat, sampled between calls. Linux only."""
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        vals = [int(x) for x in parts]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        d_total = total - _LAST_CPU["total"]
        d_idle = idle - _LAST_CPU["idle"]
        _LAST_CPU["total"], _LAST_CPU["idle"] = total, idle
        if d_total <= 0:
            return 0.0
        return round(100.0 * (d_total - d_idle) / d_total, 1)
    except Exception:
        return 0.0


def read_mem_percent():
    """Memory utilisation from /proc/meminfo. Linux only."""
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":")
                info[k.strip()] = int(v.split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        if total <= 0:
            return 0.0
        return round(100.0 * (total - avail) / total, 1)
    except Exception:
        return 0.0

class WebDashboardHandler(http.server.SimpleHTTPRequestHandler):
    def _send_json(self, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # silence per-request HTTP logging (keeps the console clean)

    def do_GET(self):
        route = urlparse(self.path)
        path = route.path
        params = parse_qs(route.query)

        if path == '/':
            body = self._get_dashboard_html().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == '/api/stats':
            now = time.time()
            active_count = sum(1 for t in ACTIVE_SENSORS.values() if now - t < 60)

            ddos_count = sum(1 for a in ALERT_HISTORY if "DDoS" in a["message"])
            scan_count = sum(1 for a in ALERT_HISTORY if "SCAN" in a["message"])
            payload_count = sum(1 for a in ALERT_HISTORY if "PAYLOAD" in a["message"])
            blacklist_count = sum(1 for a in ALERT_HISTORY if "BLACKLIST" in a["message"])

            traffic = packet_store.STORE.stats_snapshot()

            # ATT&CK roll-up: which techniques were observed, and the highest
            # risk score currently in the buffer
            technique_counts = {}
            max_risk = 0.0
            for a in ALERT_HISTORY:
                tid = a.get("technique_id")
                if tid and tid != "N/A":
                    key = "%s %s" % (tid, a.get("technique", ""))
                    technique_counts[key] = technique_counts.get(key, 0) + 1
                try:
                    max_risk = max(max_risk, float(a.get("risk_score") or 0))
                except (TypeError, ValueError):
                    pass
            top_techniques = sorted(technique_counts.items(),
                                    key=lambda kv: kv[1], reverse=True)[:5]

            stats = {
                "online_sensors": active_count,
                "total_alerts": len(ALERT_HISTORY),
                "max_risk": round(max_risk, 1),
                "top_techniques": top_techniques,
                "ddos_alerts": ddos_count,
                "scan_alerts": scan_count,
                "payload_alerts": payload_count,
                "blacklist_alerts": blacklist_count,
                "cpu_usage": read_cpu_percent(),
                "mem_usage": read_mem_percent(),
                # live traffic telemetry from the sensor's in-memory store
                "pps": traffic["pps"],
                "z_score": traffic["z_score"],
                "baseline": traffic["mean"],
                "ddos_candidate": traffic["ddos_candidate"],
                "ddos_active": traffic["ddos_active"],
                "packets_buffered": traffic["buffered"],
                "packets_total": traffic["total_seen"],
                "proto_counts": traffic["proto_counts"],
                "top_talkers": packet_store.STORE.top_talkers(5),
                "alerts": list(ALERT_HISTORY),
            }
            self._send_json(stats)

        elif path == '/api/packets':
            limit = int(params.get("limit", ["200"])[0])
            after = int(params.get("after", ["0"])[0])
            proto = params.get("proto", [None])[0]
            query = params.get("q", [None])[0]
            packets = packet_store.STORE.get_recent(
                limit=limit, proto=proto, query=query, after=after)
            self._send_json({
                "packets": packets,
                "buffered": packet_store.STORE.stats_snapshot()["buffered"],
                "total": packet_store.STORE.stats_snapshot()["total_seen"],
            })

        elif path == '/api/export':
            # download the whole in-memory capture as a JSON "pcap-lite" file
            data = json.dumps({
                "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "packets": packet_store.STORE.all_packets(),
            }, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Disposition',
                             'attachment; filename="mantis_capture.json"')
            self.end_headers()
            self.wfile.write(data)

        elif path == '/api/export.pcap':
            # Serialise the in-memory ring buffer as a real libpcap file, so
            # the captured frames can be verified independently in Wireshark
            # or tcpdump rather than only through this dashboard.
            records = packet_store.STORE.all_packets()
            data = pcap.build_from_records(records)
            self.send_response(200)
            self.send_header('Content-type', 'application/vnd.tcpdump.pcap')
            self.send_header('Content-Disposition',
                             'attachment; filename="mantis_capture.pcap"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == '/api/config':
            # expose the effective runtime policy so the operator can confirm
            # whether active defence and privacy controls are actually on
            self._send_json({
                "block_enabled": CONFIG.block_enabled,
                "block_on": CONFIG.block_on,
                "privacy_mode": CONFIG.privacy_mode,
                "anonymise_ips": CONFIG.anonymise_ips,
                "payload_excerpt_bytes": CONFIG.payload_excerpt_bytes,
                "zscore_threshold": CONFIG.zscore_threshold,
                "zscore_window": CONFIG.zscore_window,
                "ddos_min_pps": CONFIG.ddos_min_pps,
                "ddos_consecutive_intervals":
                    CONFIG.ddos_consecutive_intervals,
                "packet_buffer": CONFIG.packet_buffer,
                "pcap_file": CONFIG.pcap_file,
                "blacklist_file": CONFIG.blacklist_file,
            })

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

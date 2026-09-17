import csv
import json
import os
import socket
import threading
import time

try:
    import utils.mitre as mitre
    import utils.privacy as privacy
except ImportError:  # direct execution from inside utils/
    import mitre
    import privacy


# FR-4 requires the audit trail to record "timestamps, source IP addresses,
# engine identifiers, threat verdicts, confidence scores, and payload
# excerpts", not just a free-text line. These are the resulting columns.
CSV_COLUMNS = [
    "Timestamp",
    "Source IP",
    "Engine",
    "Verdict",
    "Severity",
    "Risk Score",
    "Confidence",
    "ATT&CK Technique",
    "ATT&CK Tactic",
    "Payload Excerpt",
    "Message",
]


class Logger:
    """Append-only CSV audit log.

    Writes are serialised through a threading.Lock because the sensor's
    analyzer thread and the main reporting loop can both emit an alert; without
    it two interleaved csv.writer calls can produce a torn row and corrupt the
    evidence file.

    Everything persisted here passes through utils.privacy first, so the
    64-byte excerpt limit and PII redaction required by NFR-3 are enforced at
    the point of writing rather than left to each caller.
    """

    def __init__(self, filename="mantis_logs.csv", config=None):
        self.filename = filename
        self.config = config
        self._lock = threading.Lock()
        self.rows_written = 0

        # (Re)create the header when the file is absent or was left empty.
        # Preserve a legacy two-column log instead of appending eleven-column
        # records below an incompatible header.
        needs_header = (not os.path.exists(self.filename)
                        or os.path.getsize(self.filename) == 0)
        if not needs_header:
            try:
                with open(self.filename, newline="", encoding="utf-8") as f:
                    current_header = next(csv.reader(f), [])
                if current_header != CSV_COLUMNS:
                    stamp = time.strftime("%Y%m%d_%H%M%S")
                    backup = "%s.legacy_%s.csv" % (self.filename, stamp)
                    suffix = 1
                    while os.path.exists(backup):
                        backup = "%s.legacy_%s_%d.csv" % (
                            self.filename, stamp, suffix)
                        suffix += 1
                    os.replace(self.filename, backup)
                    print("[*] preserved legacy audit log as %s" % backup)
                    needs_header = True
            except (OSError, csv.Error) as exc:
                print("[!] could not inspect audit-log header: %s" % exc)
        if needs_header:
            with open(self.filename, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(CSV_COLUMNS)

    def log_alert(self, message, src_ip=None, engine=None, confidence=None,
                  payload=None, verdict=None):
        """Record one alert, enriched with ATT&CK context and risk score."""
        meta = mitre.enrich(message, confidence)

        limit = getattr(self.config, "payload_excerpt_bytes", 64)
        privacy_mode = getattr(self.config, "privacy_mode", True)
        anonymise = getattr(self.config, "anonymise_ips", False)

        excerpt = privacy.payload_excerpt(payload, limit=limit,
                                          privacy_mode=privacy_mode) if payload else ""
        safe_ip = privacy.anonymise_ip(src_ip, anonymise) if src_ip else ""

        row = [
            time.strftime("%Y-%m-%d %H:%M:%S"),
            safe_ip,
            engine or meta["engine"],
            verdict or meta["kind"],
            meta["severity"],
            meta["risk_score"],
            "" if confidence is None else round(float(confidence), 4),
            "%s (%s)" % (meta["technique_id"], meta["technique"]),
            "%s (%s)" % (meta["tactic_id"], meta["tactic"]),
            excerpt,
            privacy.redact(message) if privacy_mode else message,
        ]

        try:
            with self._lock:
                with open(self.filename, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow(row)
                self.rows_written += 1
        except Exception as e:
            print("[!] log error:", e)

    def close(self):
        return self.rows_written


class UDPSender:
    """Ships alerts to the SIEM as structured JSON datagrams.

    FR-5 requires alerts to be serialised "into structured JSON objects" before
    transmission. A JSON frame also lets the dashboard render fields (severity,
    ATT&CK technique, risk score, source IP) as real columns instead of
    re-parsing an English sentence on the receiving end.

    A `ts` text field is retained so an older text-only listener still shows
    something meaningful, and so the receiver can validate the frame.
    """

    def __init__(self, target_ip, port=9999, config=None):
        self.target = (target_ip, port)
        self.config = config
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sent = 0
        self.failed = 0

    def send_log(self, message, src_ip=None, engine=None, confidence=None,
                 payload=None):
        meta = mitre.enrich(message, confidence)

        limit = getattr(self.config, "payload_excerpt_bytes", 64)
        privacy_mode = getattr(self.config, "privacy_mode", True)
        anonymise = getattr(self.config, "anonymise_ips", False)

        frame = {
            "v": 1,                                  # schema version
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "message": privacy.redact(message) if privacy_mode else message,
            "src_ip": privacy.anonymise_ip(src_ip, anonymise) if src_ip else "",
            "engine": engine or meta["engine"],
            "kind": meta["kind"],
            "severity": meta["severity"],
            "risk_score": meta["risk_score"],
            "technique_id": meta["technique_id"],
            "technique": meta["technique"],
            "tactic": meta["tactic"],
            "confidence": None if confidence is None else round(float(confidence), 4),
        }
        if payload:
            frame["payload_excerpt"] = privacy.payload_excerpt(
                payload, limit=limit, privacy_mode=privacy_mode)

        try:
            data = json.dumps(frame).encode("utf-8")
            # a UDP datagram must stay inside the path MTU to avoid
            # fragmentation; excerpts are already capped so this is a guard
            if len(data) > 1400:
                frame.pop("payload_excerpt", None)
                data = json.dumps(frame).encode("utf-8")
            self.sock.sendto(data, self.target)
            self.sent += 1
        except Exception as e:
            self.failed += 1
            print("[!] udp send error:", e)


if __name__ == "__main__":
    log = Logger("demo_logs.csv")
    log.log_alert("MALICIOUS PAYLOAD! Keywords: ['UNION', 'SELECT']",
                  src_ip="192.168.1.57", confidence=0.99,
                  payload=b"id=1 UNION SELECT password FROM users")
    log.log_alert("DDoS DETECTED! Z-Score: 4.21 (PPS: 8500)",
                  src_ip="10.0.0.9", confidence=0.88)
    print("wrote %d rows to demo_logs.csv" % log.rows_written)
    with open("demo_logs.csv", encoding="utf-8") as f:
        print(f.read())

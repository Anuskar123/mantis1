#!/usr/bin/env python3
"""System-tier test: the SIEM HTTP API and JSON telemetry path.

This is the top tier of the Chapter 6 testing strategy - it starts the real
UDP listener and the real HTTP server, sends real datagrams through a socket,
and asserts on the responses the browser would receive. It therefore verifies
FR-5 (structured JSON alert transport) and FR-6 (real-time dashboard rendering)
rather than testing them in isolation.

The test binds real ports, so it is skipped automatically if they are already
in use.
"""

import json
import os
import socket
import sys
import threading
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import sensor_node.parser as parser_mod
import utils.logger as logger_mod
import utils.packet_store as packet_store
import utils.pcap as pcap

BASE = "http://127.0.0.1:8080"


def _port_free(port, kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _get_json(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


@unittest.skipUnless(_port_free(8080) and _port_free(9999, socket.SOCK_DGRAM),
                     "ports 8080/9999 already in use")
class TestSiemApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import dashboard_ui.siem as siem
        cls.siem = siem
        threading.Thread(target=siem.start_siem, daemon=True).start()
        time.sleep(1.5)

        # populate the in-memory ring buffer with genuinely decoded frames
        parser = parser_mod.PacketParser()
        cls.frames = [
            parser_mod.build_tcp(sport=4000 + i, dport=80,
                                 data=b"GET /index.html HTTP/1.1")
            for i in range(5)
        ]
        cls.frames.append(parser_mod.build_udp(sport=5353, dport=53,
                                               data=b"dns-query"))
        cls.frames.append(parser_mod.build_icmp(icmp_type=8))

        for frame in cls.frames:
            pkt = parser.parse(frame)
            packet_store.STORE.add({
                "ts": time.time(), "time": packet_store.now_hms(),
                "src": pkt["src"], "dst": pkt["dst"], "proto": pkt["proto"],
                "sport": pkt["sport"], "dport": pkt["dport"],
                "length": pkt["length"], "info": pkt["info"],
                "verdict": "clean", "hex": frame.hex(),
            })
        packet_store.STORE.update_stats(120, 11.5, 4.2)

        # send structured JSON alerts over the wire (FR-5)
        sender = logger_mod.UDPSender("127.0.0.1", 9999)
        sender.send_log("MALICIOUS PAYLOAD! Keywords: ['UNION', 'SELECT']",
                        src_ip="192.0.2.66", confidence=0.99,
                        payload=b"id=1 UNION SELECT pw FROM users")
        sender.send_log("DDoS DETECTED! Z-Score: 5.10 (PPS: 9000)",
                        src_ip="10.0.0.9", confidence=0.9)
        sender.send_log("PORT SCAN DETECTED! (Unique Ports: 210/sec)",
                        src_ip="192.0.2.5", confidence=0.8)
        time.sleep(1.0)

    def test_stats_endpoint_reports_live_traffic(self):
        stats = _get_json("/api/stats")
        self.assertEqual(stats["pps"], 120)
        self.assertAlmostEqual(stats["z_score"], 4.2, places=3)
        self.assertFalse(stats["ddos_candidate"])
        self.assertFalse(stats["ddos_active"])
        self.assertGreaterEqual(stats["packets_buffered"], 7)
        self.assertGreaterEqual(stats["proto_counts"]["TCP"], 5)
        self.assertGreaterEqual(stats["proto_counts"]["ICMP"], 1)

    def test_dashboard_is_utf8_without_broken_symbols(self):
        with urllib.request.urlopen(BASE + "/", timeout=5) as response:
            self.assertEqual(response.headers.get_content_charset(), "utf-8")
            body = response.read().decode("utf-8")
        self.assertNotIn("â", body)
        self.assertNotIn("⭳", body)
        self.assertIn("Export .pcap (Wireshark)", body)

    def test_json_alerts_are_ingested_with_attack_context(self):
        stats = _get_json("/api/stats")
        self.assertGreaterEqual(stats["total_alerts"], 3)

        techniques = {a.get("technique_id") for a in stats["alerts"]}
        self.assertIn("T1190", techniques)   # payload  -> Initial Access
        self.assertIn("T1498", techniques)   # flood    -> Impact
        self.assertIn("T1046", techniques)   # scan     -> Discovery

        # match on source address rather than position: other tests in this
        # class also emit T1190 alerts, and execution order is alphabetical
        payload_alert = next(a for a in stats["alerts"]
                             if a.get("src_ip") == "192.0.2.66")
        self.assertEqual(payload_alert["technique_id"], "T1190")
        self.assertEqual(payload_alert["severity"], "HIGH")
        self.assertGreater(payload_alert["risk_score"], 0)

    def test_credentials_never_reach_the_dashboard(self):
        # the excerpt forwarded over UDP must already be redacted
        sender = logger_mod.UDPSender("127.0.0.1", 9999)
        sender.send_log("MALICIOUS PAYLOAD! Keywords: ['UNION']",
                        src_ip="192.0.2.7", confidence=0.95,
                        payload=b"password=hunter2&email=bob@example.com UNION")
        time.sleep(0.8)
        body = json.dumps(_get_json("/api/stats"))
        self.assertNotIn("hunter2", body)
        self.assertNotIn("bob@example.com", body)

    def test_attack_technique_rollup(self):
        stats = _get_json("/api/stats")
        self.assertTrue(stats["top_techniques"])
        self.assertGreater(stats["max_risk"], 0)

    def test_malformed_datagram_is_rejected_not_crashing(self):
        # port 9999 is itself a scan target, so raw bytes do arrive
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"\x00\x01\x02\xff\xfe not json at all", ("127.0.0.1", 9999))
        s.close()
        time.sleep(0.8)
        stats = _get_json("/api/stats")   # server must still be responsive
        self.assertIn("INVALID UDP PAYLOAD",
                      json.dumps(stats["alerts"]))

    def test_packets_endpoint_returns_decoded_rows(self):
        data = _get_json("/api/packets?limit=50")
        self.assertGreaterEqual(len(data["packets"]), 7)
        row = data["packets"][0]
        for key in ("src", "dst", "proto", "length", "info", "hex"):
            self.assertIn(key, row)

    def test_protocol_filter(self):
        icmp = _get_json("/api/packets?limit=50&proto=ICMP")["packets"]
        self.assertTrue(icmp)
        self.assertTrue(all(p["proto"] == "ICMP" for p in icmp))

    def test_config_endpoint_exposes_effective_policy(self):
        cfg = _get_json("/api/config")
        # NFR-3 defaults must be visible and safe
        self.assertFalse(cfg["block_enabled"])
        self.assertTrue(cfg["privacy_mode"])
        self.assertEqual(cfg["payload_excerpt_bytes"], 64)
        self.assertEqual(cfg["ddos_min_pps"], 500)
        self.assertEqual(cfg["ddos_consecutive_intervals"], 3)

    def test_pcap_export_is_openable_by_wireshark(self):
        with urllib.request.urlopen(BASE + "/api/export.pcap", timeout=5) as r:
            self.assertEqual(r.headers.get("Content-type"),
                             "application/vnd.tcpdump.pcap")
            raw = r.read()

        path = os.path.join(HERE, "_siem_export.pcap")
        try:
            with open(path, "wb") as f:
                f.write(raw)

            reader = pcap.PcapReader(path)          # validates the magic number
            self.assertEqual(reader.linktype, pcap.LINKTYPE_ETHERNET)
            recovered = list(reader)
            reader.close()

            self.assertGreaterEqual(len(recovered), 7)
            # each exported frame must decode back into a real packet
            parser = parser_mod.PacketParser()
            for _ts, data, _orig in recovered:
                self.assertIsNotNone(parser.parse(data))
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

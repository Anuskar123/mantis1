#!/usr/bin/env python3
"""Integration tier of the V-Model test strategy.

Chapter 6.1 defines three testing tiers - unit, integration and system-level.
`test_engines.py` covers the unit tier by exercising each engine's mathematics
in isolation. This module covers the integration tier: it verifies that the
components work correctly *together* along the real data path

    raw frame -> PacketParser -> engines -> AlertDispatcher -> log / telemetry
                                                            -> PacketStore
                                                            -> pcap export

Nothing here needs root, a network interface or live attack traffic, so the
integration tier is reproducible on any machine.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import replay
import sensor_node.dispatcher as dispatcher_mod
import sensor_node.parser as parser_mod
import sensor_node.sensor as sensor_mod
import utils.logger as logger_mod
import utils.packet_store as packet_store
import utils.pcap as pcap
from utils.config import Config


class _RecordingDefense:
    """Stands in for iptables so tests never touch the host firewall."""

    def __init__(self):
        self.blocked = []

    def block_ip(self, ip):
        self.blocked.append(ip)
        return True


class TestParserToEngines(unittest.TestCase):
    """A synthetic attack frame must survive decode and reach a verdict."""

    def setUp(self):
        self.parser = parser_mod.PacketParser()

    def test_sqli_frame_decodes_and_is_flagged(self):
        import engines.naive_bayes as nb
        frame = parser_mod.build_tcp(
            sport=44000, dport=80,
            data=b"GET /?id=1 UNION SELECT password FROM users --")
        pkt = self.parser.parse(frame)

        self.assertIsNotNone(pkt)
        self.assertEqual(pkt["proto"], "TCP")
        self.assertEqual(pkt["dport"], 80)

        verdict = nb.PayloadMonitor().analyse(pkt["payload"])
        self.assertTrue(verdict.is_threat)
        self.assertIn("UNION", verdict.detail["keywords"])

    def test_benign_frame_is_not_flagged(self):
        import engines.naive_bayes as nb
        frame = parser_mod.build_tcp(data=b"GET /index.html HTTP/1.1\r\n")
        pkt = self.parser.parse(frame)
        self.assertFalse(nb.PayloadMonitor().analyse(pkt["payload"]).is_threat)

    def test_truncated_frame_does_not_raise(self):
        # a malformed frame must be rejected, not crash the analyzer thread
        for bad in (b"", b"\x00" * 8, b"\xff" * 20, None):
            self.assertIsNone(self.parser.parse(bad))
        self.assertEqual(self.parser.parsed, 0)

    def test_vlan_tagged_frame_is_decoded(self):
        import struct
        inner = parser_mod.build_tcp(sport=1234, dport=443)
        # splice an 802.1Q tag between the MAC addresses and the EtherType
        tagged = (inner[:12] + struct.pack("!HH", 0x8100, 0x0064)
                  + struct.pack("!H", 0x0800) + inner[14:])
        pkt = self.parser.parse(tagged)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt["dport"], 443)

    def test_icmp_frame_is_decoded(self):
        pkt = self.parser.parse(parser_mod.build_icmp(icmp_type=8))
        self.assertEqual(pkt["proto"], "ICMP")
        self.assertEqual(pkt["icmp_type"], 8)


class TestDispatcherFanOut(unittest.TestCase):
    """One dispatch call must reach every configured sink exactly once."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.config = Config()
        self.config.log_file = os.path.join(self.tmp, "alerts.csv")
        self.logger = logger_mod.Logger(self.config.log_file,
                                        config=self.config)
        self.defense = _RecordingDefense()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _dispatcher(self):
        return dispatcher_mod.AlertDispatcher(
            self.config, logger=self.logger, defense=self.defense)

    def test_alert_written_with_all_fr4_columns(self):
        d = self._dispatcher()
        d.dispatch("MALICIOUS PAYLOAD! Keywords: ['UNION']",
                   src_ip="192.0.2.5", confidence=0.97,
                   payload=b"id=1 UNION SELECT pw FROM users")

        import csv
        with open(self.config.log_file, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        self.assertEqual(len(rows), 1)
        row = rows[0]
        for column in ("Timestamp", "Source IP", "Engine", "Verdict",
                       "Severity", "Risk Score", "Confidence",
                       "ATT&CK Technique", "Payload Excerpt"):
            self.assertIn(column, row)
        self.assertEqual(row["Source IP"], "192.0.2.5")
        self.assertIn("T1190", row["ATT&CK Technique"])
        self.assertTrue(float(row["Risk Score"]) > 0)

        legacy = os.path.join(self.tmp, "legacy.csv")
        with open(legacy, "w", encoding="utf-8") as f:
            f.write("Timestamp,Alert Message\nold,event\n")
        logger_mod.Logger(legacy, config=self.config)
        with open(legacy, encoding="utf-8") as f:
            self.assertEqual(f.readline().strip(),
                             ",".join(logger_mod.CSV_COLUMNS))
        backups = [name for name in os.listdir(self.tmp)
                   if name.startswith("legacy.csv.legacy_")]
        self.assertEqual(len(backups), 1)

    def test_blocking_disabled_by_default(self):
        # NFR-3: active defence must be opt-in
        d = self._dispatcher()
        d.dispatch("DDoS DETECTED! Z-Score: 9.1 (PPS: 9000)", src_ip="10.0.0.5")
        self.assertEqual(self.defense.blocked, [])

    def test_blocking_when_enabled(self):
        self.config.block_enabled = True
        d = self._dispatcher()
        d.dispatch("DDoS DETECTED! Z-Score: 9.1 (PPS: 9000)", src_ip="10.0.0.5")
        self.assertEqual(self.defense.blocked, ["10.0.0.5"])

    def test_response_status_says_flagged_when_blocking_is_disabled(self):
        d = self._dispatcher()
        d.dispatch("BLACKLISTED IP DETECTED: 10.0.0.66",
                   kind="blacklist", src_ip="10.0.0.66",
                   response_status=True)
        with open(self.config.log_file, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("(Flagged)", body)
        self.assertNotIn("(Blocked)", body)

    def test_response_status_says_blocked_only_after_success(self):
        self.config.block_enabled = True
        d = self._dispatcher()
        meta = d.dispatch("BLACKLISTED IP DETECTED: 10.0.0.66",
                          kind="blacklist", src_ip="10.0.0.66",
                          response_status=True)
        with open(self.config.log_file, encoding="utf-8") as f:
            body = f.read()
        self.assertTrue(meta["blocked"])
        self.assertIn("(Blocked)", body)

    def test_every_engine_kind_can_trigger_a_block(self):
        # Chapter 5.7 states that *any* engine may trigger a block
        self.config.block_enabled = True
        d = self._dispatcher()
        cases = [
            ("DDoS DETECTED! Z-Score: 9.1 (PPS: 9000)", "10.0.0.1"),
            ("PORT SCAN DETECTED! (Unique Ports: 90/sec)", "10.0.0.2"),
            ("MALICIOUS PAYLOAD! Keywords: ['UNION']", "10.0.0.3"),
            ("BLACKLISTED IP DETECTED: 10.0.0.4 (Flagged)", "10.0.0.4"),
        ]
        for message, ip in cases:
            d.dispatch(message, src_ip=ip)
        self.assertEqual(self.defense.blocked,
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    def test_whitelisted_ip_is_never_blocked(self):
        self.config.block_enabled = True
        d = self._dispatcher()
        d.dispatch("DDoS DETECTED! Z-Score: 9.1 (PPS: 9000)",
                   src_ip="127.0.0.1")
        self.assertEqual(self.defense.blocked, [])

    def test_duplicate_block_inserted_once(self):
        self.config.block_enabled = True
        d = self._dispatcher()
        for _ in range(5):
            d.dispatch("DDoS DETECTED! Z-Score: 9.1 (PPS: 9000)",
                       src_ip="10.0.0.9")
        self.assertEqual(self.defense.blocked, ["10.0.0.9"])

    def test_duplicate_alert_is_published_once(self):
        d = self._dispatcher()
        for _ in range(2):
            d.dispatch("MALICIOUS PAYLOAD! Keywords: ['UNION']",
                       src_ip="192.0.2.55", confidence=0.95)
        self.assertEqual(d.total, 1)
        self.assertEqual(self.logger.rows_written, 1)

    def test_pii_is_redacted_before_persistence(self):
        # NFR-3 / DPA 2018: credentials must not reach the audit log
        d = self._dispatcher()
        d.dispatch("MALICIOUS PAYLOAD! Keywords: ['UNION']",
                   src_ip="192.0.2.9", confidence=0.9,
                   payload=b"user=bob@example.com&password=hunter2&id=1 UNION")
        with open(self.config.log_file, encoding="utf-8") as f:
            body = f.read()
        self.assertNotIn("bob@example.com", body)
        self.assertNotIn("hunter2", body)
        self.assertIn("REDACTED", body)


class TestPacketStoreToPcap(unittest.TestCase):
    """The in-memory buffer must serialise to a file Wireshark can read."""

    def setUp(self):
        self.store = packet_store.PacketStore(maxlen=50)
        self.parser = parser_mod.PacketParser()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_buffer_exports_as_readable_pcap(self):
        frames = [parser_mod.build_tcp(sport=5000 + i, dport=80,
                                       data=b"GET / HTTP/1.1")
                  for i in range(6)]
        frames.append(parser_mod.build_udp(data=b"dns"))
        frames.append(parser_mod.build_icmp())

        for frame in frames:
            pkt = self.parser.parse(frame)
            self.store.add({
                "ts": 1700000000.5, "time": "12:00:00",
                "src": pkt["src"], "dst": pkt["dst"], "proto": pkt["proto"],
                "sport": pkt["sport"], "dport": pkt["dport"],
                "length": pkt["length"], "info": pkt["info"],
                "verdict": "clean", "hex": frame.hex(),
            })

        data = pcap.build_from_records(self.store.all_packets())
        path = os.path.join(self.tmp, "out.pcap")
        with open(path, "wb") as f:
            f.write(data)

        reader = pcap.PcapReader(path)
        self.assertEqual(reader.linktype, pcap.LINKTYPE_ETHERNET)
        recovered = list(reader)
        reader.close()

        self.assertEqual(len(recovered), len(frames))
        # every recovered frame must decode back to the same 5-tuple
        for (_ts, raw, _orig), original in zip(recovered, frames):
            self.assertEqual(raw, original)
            self.assertIsNotNone(parser_mod.PacketParser().parse(raw))

    def test_ring_buffer_is_bounded(self):
        for i in range(200):
            self.store.add({"ts": 0, "src": "1.1.1.1", "proto": "TCP",
                            "length": 60, "hex": "00"})
        self.assertEqual(self.store.stats_snapshot()["buffered"], 50)
        self.assertEqual(self.store.stats_snapshot()["total_seen"], 200)


class TestIntervalSourceAttribution(unittest.TestCase):
    """Aggregate alerts may name a source only when dominance is defensible."""

    def setUp(self):
        self.sensor = sensor_mod.SensorNode.__new__(sensor_mod.SensorNode)
        self.sensor.config = Config()

    def test_dominant_source_is_attributed_above_threshold(self):
        stats = {
            "192.0.2.10": {"packets": 80, "ports": set()},
            "192.0.2.20": {"packets": 20, "ports": set()},
        }
        self.assertEqual(
            self.sensor._dominant_source(stats, 100), "192.0.2.10")

    def test_distributed_traffic_is_not_attributed_or_blockable(self):
        stats = {
            "192.0.2.10": {"packets": 40, "ports": set()},
            "192.0.2.20": {"packets": 35, "ports": set()},
            "192.0.2.30": {"packets": 25, "ports": set()},
        }
        self.assertIsNone(self.sensor._dominant_source(stats, 100))


class TestReplayPipeline(unittest.TestCase):
    """Generate a scenario capture, replay it, and check the right engines fire."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "scenario.pcap")
        replay.generate_scenario(cls.path)
        cls.summary = replay.ReplayEngine().run(cls.path, verbose=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_capture_is_valid_pcap(self):
        reader = pcap.PcapReader(self.path)
        self.assertEqual(reader.linktype, pcap.LINKTYPE_ETHERNET)
        reader.close()

    def test_all_frames_decode_without_error(self):
        self.assertGreater(self.summary["packets"], 1000)
        self.assertEqual(self.summary["parser"]["malformed"], 0)

    def test_every_engine_detects_its_own_attack(self):
        hits = self.summary["engine_hits"]
        for engine in ("z_score", "knn", "naive_bayes", "bloom", "kmeans"):
            self.assertGreater(hits[engine], 0,
                               "%s produced no detections" % engine)

    def test_port_scan_detected_only_during_scan_window(self):
        # the generated scan runs from t=15s to t=20s
        scan_times = [a["t"] for a in self.summary["alerts"]
                      if a["engine"] == "knn"]
        self.assertTrue(scan_times)
        for t in scan_times:
            self.assertGreaterEqual(t, 15.0)
            self.assertLess(t, 20.0)

    def test_normal_baseline_produces_no_alerts(self):
        baseline_alerts = [
            alert for alert in self.summary["alerts"] if alert["t"] < 15.0
        ]
        self.assertEqual(baseline_alerts, [])

    def test_controlled_interval_attacks_have_source_attribution(self):
        for alert in self.summary["alerts"]:
            if alert["engine"] in ("z_score", "knn", "kmeans"):
                self.assertTrue(
                    alert["src"],
                    "%s alert was not attributed" % alert["engine"])

    def test_alerts_carry_attack_technique_and_risk(self):
        for alert in self.summary["alerts"]:
            self.assertTrue(alert["technique_id"])
            self.assertNotEqual(alert["technique_id"], "N/A")
            self.assertGreater(alert["risk_score"], 0)


class TestBrainRoundTripAcrossEngines(unittest.TestCase):
    """A saved brain must restore every engine's learned state (FR-8)."""

    def test_all_five_engines_round_trip(self):
        import engines.bloom as bloom
        import engines.kmeans as kmeans
        import engines.knn as knn
        import engines.naive_bayes as nb
        import engines.z_score as zs

        original = {
            "z_score": zs.MinimalistStats(window_size=10),
            "knn": knn.KNNMonitor(k=3),
            "payload": nb.PayloadMonitor(),
            "kmeans": kmeans.KMeansMonitor(k=3),
            "bloom": bloom.BloomFilter(size=200, hash_count=3),
        }

        # give each engine something to learn
        for pps in [10, 12, 11, 13, 9, 10, 12]:
            original["z_score"].analyse(pps)
        for _ in range(12):
            original["kmeans"].analyse(11, 2)
        original["bloom"].add("192.0.2.66")

        brain = {k: e.export_brain() for k, e in original.items()}
        # must survive a real JSON serialisation, not just an in-memory dict
        brain = json.loads(json.dumps(brain))

        restored = {
            "z_score": zs.MinimalistStats(window_size=10),
            "knn": knn.KNNMonitor(k=3),
            "payload": nb.PayloadMonitor(),
            "kmeans": kmeans.KMeansMonitor(k=3),
            "bloom": bloom.BloomFilter(size=200, hash_count=3),
        }
        for key, engine in restored.items():
            self.assertTrue(engine.import_brain(brain[key]),
                            "%s failed to import its brain" % key)

        self.assertAlmostEqual(restored["z_score"].w_mean,
                               original["z_score"].w_mean)
        self.assertEqual(restored["kmeans"].centroids,
                         original["kmeans"].centroids)
        self.assertTrue(restored["bloom"].check("192.0.2.66"))
        self.assertEqual(set(restored["payload"].likelihoods),
                         set(original["payload"].likelihoods))


if __name__ == "__main__":
    unittest.main(verbosity=2)

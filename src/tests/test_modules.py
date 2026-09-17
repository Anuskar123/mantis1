#!/usr/bin/env python3
"""Unit tests for the supporting modules and the algorithmic corrections.

Covers the parts of the system that are not detection engines themselves but
that the requirements depend on:

    utils.privacy   NFR-3 / DPA 2018 data minimisation
    utils.pcap      libpcap encoding and decoding
    utils.mitre     ATT&CK mapping and risk scoring
    utils.config    configuration precedence, opt-in defaults

plus regression tests for the three algorithmic defects found while building
the replay harness: Z-Score baseline poisoning, KNN feature scaling and
K-Means novelty detection.
"""

import math
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import utils.mitre as mitre
import utils.pcap as pcap
import utils.privacy as privacy
from engines import bloom, kmeans, knn, z_score
from utils.config import Config


class TestPrivacy(unittest.TestCase):
    def test_excerpt_truncated_to_64_bytes(self):
        # NFR-3 states payload excerpts are truncated to 64 bytes
        long_payload = b"A" * 500
        self.assertEqual(len(privacy.payload_excerpt(long_payload, limit=64)),
                         64)

    def test_email_is_redacted(self):
        out = privacy.payload_excerpt(b"contact=alice@example.com", limit=200)
        self.assertNotIn("alice@example.com", out)
        self.assertIn("EMAIL_REDACTED", out)

    def test_password_and_token_are_redacted(self):
        out = privacy.payload_excerpt(b"password=hunter2&api_key=sk_live_99",
                                      limit=200)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("sk_live_99", out)

    def test_card_number_is_redacted(self):
        out = privacy.payload_excerpt(b"card=4111111111111111", limit=200)
        self.assertNotIn("4111111111111111", out)

    def test_control_bytes_cannot_reach_the_log(self):
        # log-injection defence: escapes and newlines become '.'
        out = privacy.payload_excerpt(b"a\x1b[31mred\x00\nb", limit=64)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\n", out)
        self.assertNotIn("\x00", out)

    def test_privacy_mode_off_keeps_content(self):
        out = privacy.payload_excerpt(b"password=hunter2", limit=64,
                                      privacy_mode=False)
        self.assertIn("hunter2", out)

    def test_ip_anonymisation_masks_host_octet(self):
        self.assertEqual(privacy.anonymise_ip("192.168.1.57"), "192.168.1.0")
        # disabled by default when the flag is off
        self.assertEqual(privacy.anonymise_ip("192.168.1.57", False),
                         "192.168.1.57")

    def test_non_ipv4_input_is_left_alone(self):
        self.assertEqual(privacy.anonymise_ip("not-an-ip"), "not-an-ip")


class TestPcap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "t.pcap")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_then_read_round_trip(self):
        frames = [b"\xaa" * 60, b"\xbb" * 74, b"\xcc" * 128]
        with pcap.PcapWriter(self.path) as w:
            for i, f in enumerate(frames):
                w.write(f, ts=1700000000 + i)

        with pcap.PcapReader(self.path) as r:
            out = list(r)

        self.assertEqual([d for _, d, _ in out], frames)
        self.assertEqual([int(ts) for ts, _, _ in out],
                         [1700000000, 1700000001, 1700000002])

    def test_global_header_is_libpcap_conformant(self):
        with pcap.PcapWriter(self.path, snaplen=96) as w:
            w.write(b"\x00" * 40)
        with open(self.path, "rb") as f:
            head = f.read(24)
        self.assertEqual(len(head), 24)
        import struct
        magic, major, minor, tz, sig, snap, link = struct.unpack("<IHHiIII",
                                                                 head)
        self.assertEqual(magic, pcap.MAGIC_MICRO)
        self.assertEqual((major, minor), (2, 4))
        self.assertEqual(snap, 96)
        self.assertEqual(link, pcap.LINKTYPE_ETHERNET)

    def test_snaplen_truncates_but_records_original_length(self):
        # a header-only capture must still report the true on-wire size
        with pcap.PcapWriter(self.path, snaplen=32) as w:
            w.write(b"\x11" * 1514)
        with pcap.PcapReader(self.path) as r:
            ts, data, orig = next(iter(r))
        self.assertEqual(len(data), 32)
        self.assertEqual(orig, 1514)

    def test_microsecond_precision_preserved(self):
        with pcap.PcapWriter(self.path) as w:
            w.write(b"\x00" * 20, ts=1700000000.123456)
        with pcap.PcapReader(self.path) as r:
            ts, _, _ = next(iter(r))
        self.assertAlmostEqual(ts, 1700000000.123456, places=5)

    def test_rejects_non_pcap_file(self):
        with open(self.path, "wb") as f:
            f.write(b"this is not a capture file at all")
        with self.assertRaises(pcap.PcapError):
            pcap.PcapReader(self.path)

    def test_big_endian_capture_is_readable(self):
        # captures written on a big-endian host must still parse
        import struct
        with open(self.path, "wb") as f:
            f.write(struct.pack(">IHHiIII", pcap.MAGIC_MICRO, 2, 4, 0, 0,
                                65535, 1))
            f.write(struct.pack(">IIII", 1700000000, 500, 4, 4) + b"\xde\xad\xbe\xef")
        with pcap.PcapReader(self.path) as r:
            self.assertEqual(r.endian, ">")
            ts, data, orig = next(iter(r))
        self.assertEqual(data, b"\xde\xad\xbe\xef")


class TestMitre(unittest.TestCase):
    def test_each_detection_maps_to_expected_technique(self):
        cases = [
            ("DDoS DETECTED! Z-Score: 4.2 (PPS: 9000)", "T1498"),
            ("PORT SCAN DETECTED! (Unique Ports: 90/sec)", "T1046"),
            ("MALICIOUS PAYLOAD! Keywords: ['UNION', 'SELECT']", "T1190"),
            ("BLACKLISTED IP DETECTED: 10.0.0.5 (Flagged)", "T1071"),
        ]
        for message, technique in cases:
            self.assertEqual(mitre.enrich(message)["technique_id"], technique)

    def test_payload_families_are_distinguished(self):
        self.assertEqual(mitre.classify_kind(
            "MALICIOUS PAYLOAD! Keywords: ['UNION']"), "sqli")
        self.assertEqual(mitre.classify_kind(
            "MALICIOUS PAYLOAD! Keywords: ['SCRIPT', 'ALERT(']"), "xss")
        self.assertEqual(mitre.classify_kind(
            "MALICIOUS PAYLOAD! Keywords: ['/ETC/PASSWD']"), "lfi")

    def test_risk_score_is_bounded(self):
        for kind in mitre.TECHNIQUES:
            for conf in (None, 0.0, 0.5, 1.0):
                score = mitre.risk_score(kind, conf)
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 10.0)

    def test_confidence_scales_risk_without_saturating(self):
        low = mitre.risk_score("sqli", 0.1)
        high = mitre.risk_score("sqli", 1.0)
        self.assertLess(low, high)
        self.assertLessEqual(high, mitre.TECHNIQUES["sqli"]["base_score"])

    def test_severe_low_confidence_outranks_mild_high_confidence(self):
        self.assertGreater(mitre.risk_score("sqli", 0.1),
                           mitre.risk_score("anomaly", 1.0))

    def test_payload_families_group_for_policy(self):
        for kind in ("sqli", "xss", "lfi", "payload"):
            self.assertEqual(mitre.parent_kind(kind), "payload")
        self.assertEqual(mitre.parent_kind("ddos"), "ddos")

    def test_unknown_message_is_not_fabricated(self):
        self.assertEqual(mitre.enrich("something unrelated")["technique_id"],
                         "N/A")


class TestConfig(unittest.TestCase):
    def test_blocking_is_off_by_default(self):
        # NFR-3: active defence must be opt-in
        self.assertFalse(Config().block_enabled)

    def test_privacy_defaults_match_nfr3(self):
        c = Config()
        self.assertTrue(c.privacy_mode)
        self.assertEqual(c.payload_excerpt_bytes, 64)

    def test_loopback_is_whitelisted_by_default(self):
        self.assertIn("127.0.0.1", Config().block_whitelist)

    def test_env_overrides_defaults_with_type_coercion(self):
        c = Config()
        c.load_env({"MANTIS_BLOCK_ENABLED": "true",
                    "MANTIS_ZSCORE_THRESHOLD": "4.5",
                    "MANTIS_ZSCORE_WINDOW": "60",
                    "MANTIS_BLOCK_ON": "ddos,scan"})
        self.assertIs(c.block_enabled, True)
        self.assertEqual(c.zscore_threshold, 4.5)
        self.assertEqual(c.zscore_window, 60)
        self.assertEqual(c.block_on, ["ddos", "scan"])

    def test_json_file_round_trip(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "c.json")
            import json
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"zscore_threshold": 2.5, "http_port": 9090}, f)
            c = Config()
            self.assertTrue(c.load_file(path))
            self.assertEqual(c.zscore_threshold, 2.5)
            self.assertEqual(c.http_port, 9090)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_bad_env_value_does_not_crash(self):
        c = Config()
        c.load_env({"MANTIS_ZSCORE_WINDOW": "not-a-number"})
        self.assertEqual(c.zscore_window, 30)  # default retained


class TestZScoreCorrections(unittest.TestCase):
    """Regression tests for the flood-recall defect."""

    BASELINE = [10, 12, 11, 10, 13, 9, 11, 12, 10, 11]

    def test_welford_matches_two_pass_variance(self):
        e = z_score.MinimalistStats(window_size=100)
        for v in self.BASELINE:
            e.update(v)
        mean, std = e.welford_baseline()
        ref_mean = sum(self.BASELINE) / len(self.BASELINE)
        ref_std = math.sqrt(sum((x - ref_mean) ** 2 for x in self.BASELINE)
                            / len(self.BASELINE))
        self.assertAlmostEqual(mean, ref_mean, places=10)
        self.assertAlmostEqual(std, ref_std, places=10)

    def test_welford_is_stable_on_large_magnitudes(self):
        # the naive sum-of-squares form loses precision here; Welford must not
        e = z_score.MinimalistStats(window_size=10)
        for v in (1e8, 1e8 + 1, 1e8 + 2, 1e8 + 3):
            e.update(v)
        _, std = e.welford_baseline()
        self.assertAlmostEqual(std, math.sqrt(1.25), places=6)

    def test_sustained_flood_is_detected_throughout(self):
        # the poisoning guard must keep alerting for the whole attack
        e = z_score.MinimalistStats(window_size=10, threshold=3.0)
        e.train(self.BASELINE)
        detections = sum(1 for _ in range(60) if e.analyse(8000).is_threat)
        self.assertEqual(detections, 60)

    def test_naive_baseline_absorbs_the_flood(self):
        # documents the defect the guard fixes: without it recall collapses
        e = z_score.MinimalistStats(window_size=10, threshold=3.0,
                                    guard_baseline=False)
        e.train(self.BASELINE)
        detections = sum(1 for _ in range(60) if e.analyse(8000).is_threat)
        self.assertLess(detections, 5)

    def test_normal_traffic_raises_no_alert(self):
        e = z_score.MinimalistStats(window_size=10, threshold=3.0)
        e.train(self.BASELINE)
        for v in [10, 11, 12, 10, 9, 11, 13, 10]:
            self.assertFalse(e.analyse(v).is_threat)

    def test_low_volume_spike_is_not_mislabeled_as_ddos(self):
        e = z_score.MinimalistStats(
            window_size=10, threshold=3.0, min_pps=500)
        e.train(self.BASELINE)
        verdict = e.analyse(75)
        self.assertGreater(verdict.detail["z_score"], 3.0)
        self.assertTrue(verdict.detail["statistical_anomaly"])
        self.assertFalse(verdict.detail["volume_candidate"])
        self.assertFalse(verdict.is_threat)
        self.assertEqual(e.history[-1], 75)

    def test_live_sensor_requires_sustained_high_volume_spike(self):
        e = z_score.MinimalistStats(
            window_size=10, threshold=3.0, min_pps=500,
            required_consecutive=3)
        e.train(self.BASELINE)
        self.assertFalse(e.analyse(8000).is_threat)
        self.assertFalse(e.analyse(8000).is_threat)
        third = e.analyse(8000)
        self.assertTrue(third.is_threat)
        self.assertTrue(third.detail["new_threat"])
        fourth = e.analyse(8000)
        self.assertTrue(fourth.is_threat)
        self.assertFalse(fourth.detail["new_threat"])

    def test_no_alert_before_warm_up(self):
        # a cold engine must not fire on its first observations
        e = z_score.MinimalistStats(window_size=30, threshold=3.0)
        self.assertFalse(e.analyse(50000).is_threat)

    def test_single_outlier_z_ceiling(self):
        e = z_score.MinimalistStats(window_size=10)
        for v in self.BASELINE:
            e.update(v)
        self.assertAlmostEqual(e.max_detectable_z, 9 / math.sqrt(10), places=6)


class TestKNNFeatureScaling(unittest.TestCase):
    """Regression tests for the flood-misclassified-as-scan defect."""

    def setUp(self):
        self.e = knn.KNNMonitor(k=3)

    def test_flood_is_not_reported_as_a_port_scan(self):
        for pps in (1500, 4000, 8000, 15000):
            verdict, _ = self.e.classify(1, pps)
            self.assertEqual(verdict, "Normal",
                             "1 port @ %d pps misread as a scan" % pps)

    def test_zero_ports_can_never_be_a_scan(self):
        # Regression: an imported CIC-derived brain once labeled this Scan.
        self.e.train([[0, 50, "Scan"], [0, 100, "Scan"],
                      [100, 120, "Scan"]])
        self.assertEqual(self.e.training_data[0][2], "Normal")
        verdict = self.e.analyse(0, 75)
        self.assertEqual(verdict.label, "Normal")
        self.assertFalse(verdict.is_threat)

    def test_low_port_ratio_is_not_a_scan(self):
        # High packet volume over a few ports is browsing or a flood, not a
        # horizontal port scan.
        self.e.train([[100, 6000, "Scan"], [50, 3000, "Scan"],
                      [1, 50, "Normal"]])
        self.assertEqual(self.e.classify(25, 1000)[0], "Normal")

    def test_scan_still_detected(self):
        for ports, pps in ((45, 50), (200, 200), (400, 800)):
            verdict, _ = self.e.classify(ports, pps)
            self.assertEqual(verdict, "Scan")

    def test_normal_browsing_still_normal(self):
        # realistic client profiles: many packets spread over few ports
        for ports, pps in ((1, 5), (2, 12), (12, 75), (25, 150), (27, 160)):
            self.assertEqual(self.e.classify(ports, pps)[0], "Normal",
                             "%d ports / %d pkts misread as a scan"
                             % (ports, pps))

    def test_low_volume_stealth_scan_is_detected(self):
        # A deliberately slow scan stays below any volumetric threshold, so
        # only the ports/packets ratio can catch it: 20 ports in 30 packets
        # cannot be 20 completed TCP conversations.
        for ports, pps in ((20, 30), (12, 18), (30, 40)):
            self.assertEqual(self.e.classify(ports, pps)[0], "Scan",
                             "stealth scan %d ports / %d pkts missed"
                             % (ports, pps))

    def test_ratio_feature_separates_the_classes(self):
        # the engineered third feature is what makes the boundary separable
        ranges = self.e.feature_ranges()
        self.assertEqual(len(ranges), 3)
        self.assertEqual(self.e._features(30, 40)[2], 0.75)
        self.assertEqual(self.e._features(1, 1000)[2], 0.001)

    def test_features_are_normalised_to_unit_range(self):
        low, high = self.e.feature_ranges()[0]
        self.assertEqual(self.e._scale([low, 0, 0])[0], 0.0)
        self.assertEqual(self.e._scale([high, 0, 0])[0], 1.0)

    def test_scaling_recomputed_after_training(self):
        before = self.e.feature_ranges()
        self.e.train([[5, 20, "Normal"], [900, 3000, "Scan"]])
        self.assertNotEqual(before, self.e.feature_ranges())


class TestKMeansNovelty(unittest.TestCase):
    """Regression tests for the engine that previously never fired."""

    def _warm(self, alpha=0.1, samples=25):
        e = kmeans.KMeansMonitor(k=3, learning_rate=alpha)
        for i in range(samples):
            e.analyse(10 + (i % 3), 2)
        return e

    def test_no_alert_during_warm_up(self):
        e = kmeans.KMeansMonitor(k=3)
        self.assertFalse(e.analyse(9000, 400).is_threat)

    def test_familiar_traffic_is_not_flagged(self):
        e = self._warm()
        for _ in range(10):
            self.assertFalse(e.analyse(11, 2).is_threat)

    def test_novel_traffic_is_flagged(self):
        e = self._warm()
        for pps, ports in ((9000, 1), (60, 45), (300, 400)):
            self.assertTrue(e.analyse(pps, ports).is_threat,
                            "pps=%d ports=%d not flagged" % (pps, ports))

    def test_anomalies_do_not_poison_the_model(self):
        e = self._warm()
        baseline_before = e.distance_baseline()
        for _ in range(30):
            e.analyse(9000, 1)
        self.assertEqual(e.distance_baseline(), baseline_before)
        # and it is still alerting after 30 seconds of attack
        self.assertTrue(e.analyse(9000, 1).is_threat)

    def test_confidence_grows_with_distance(self):
        e = self._warm()
        near = e.analyse(60, 45).confidence
        far = e.analyse(90000, 1).confidence
        self.assertGreater(far, near)


class TestBloomThreatIntel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "feed.txt")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("# comment line\n"
                    "\n"
                    "192.0.2.1\n"
                    "198.51.100.23  # inline note\n"
                    "203.0.113.5,csv style comment\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_feed_loads_and_strips_comments(self):
        bf = bloom.BloomFilter(size=500, hash_count=3)
        self.assertEqual(bf.load_feed(self.path), 3)
        for ip in ("192.0.2.1", "198.51.100.23", "203.0.113.5"):
            self.assertTrue(bf.check(ip), "%s not loaded" % ip)

    def test_unlisted_address_is_clean(self):
        bf = bloom.BloomFilter(size=500, hash_count=3)
        bf.load_feed(self.path)
        self.assertFalse(bf.check("8.8.8.8"))

    def test_missing_feed_reports_failure(self):
        bf = bloom.BloomFilter(size=100, hash_count=3)
        self.assertEqual(bf.load_feed(os.path.join(self.tmp, "nope.txt")), -1)

    def test_false_positive_rate_grows_with_saturation(self):
        bf = bloom.BloomFilter(size=64, hash_count=3)
        start = bf.false_positive_rate()
        for i in range(20):
            bf.add("10.0.0.%d" % i)
        self.assertGreater(bf.false_positive_rate(), start)

    def test_no_false_negatives(self):
        # the defining Bloom guarantee: anything added is always found
        bf = bloom.BloomFilter(size=2000, hash_count=4)
        added = ["172.16.%d.%d" % (i, j) for i in range(10) for j in range(10)]
        for ip in added:
            bf.add(ip)
        for ip in added:
            self.assertTrue(bf.check(ip))


if __name__ == "__main__":
    unittest.main(verbosity=2)

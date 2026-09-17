# unit tests for the detection engines (no root, no sockets)
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from engines import bloom, kmeans, knn, naive_bayes, z_score


class TestZScore(unittest.TestCase):
    def test_constant_traffic_has_zero_stddev(self):
        e = z_score.MinimalistStats(window_size=10)
        for _ in range(10):
            e.update(20)
        m, s = e.calculate_baseline()
        self.assertAlmostEqual(m, 20.0)
        self.assertAlmostEqual(s, 0.0)

    def test_spike_triggers_high_z(self):
        e = z_score.MinimalistStats(window_size=10)
        for _ in range(9):
            e.update(10)
        e.update(11)
        m, s = e.calculate_baseline()
        z = (500 - m) / s if s > 0 else 0
        self.assertGreater(z, 3.0)


class TestKNN(unittest.TestCase):
    def setUp(self):
        self.e = knn.KNNMonitor(k=3)

    def test_normal_browsing(self):
        v, _ = self.e.classify(2, 12)
        self.assertEqual(v, "Normal")

    def test_aggressive_scan(self):
        v, _ = self.e.classify(400, 800)
        self.assertEqual(v, "Scan")

    def test_export_import_round_trip(self):
        snap = self.e.export_brain()
        fresh = knn.KNNMonitor(k=3)
        fresh.training_data = []
        fresh.import_brain(snap)
        self.assertEqual(len(fresh.training_data),
                         len(self.e.training_data))


class TestNaiveBayes(unittest.TestCase):
    def setUp(self):
        self.e = naive_bayes.PayloadMonitor()

    def test_normal_http_is_safe(self):
        v, _, _ = self.e.classify(b"GET /index.html HTTP/1.1")
        self.assertEqual(v, "Safe")

    def test_sqli_is_malicious(self):
        v, conf, words = self.e.classify(
            b"GET /?id=1 UNION SELECT password FROM users --")
        self.assertEqual(v, "Malicious")
        self.assertGreaterEqual(conf, 0.80)
        self.assertIn("UNION", words)

    def test_admin_alone_is_never_malicious(self):
        # Simulate an overconfident imported model like the one that caused
        # duplicate ADMIN alerts in the live dashboard.
        self.e.prior_malicious = 0.5
        self.e.prior_safe = 0.5
        self.e.likelihoods = {"ADMIN": (0.99, 0.01)}
        verdict, confidence, words = self.e.classify(b"GET /admin HTTP/1.1")
        self.assertGreater(confidence, 0.80)
        self.assertEqual(words, ["ADMIN"])
        self.assertEqual(verdict, "Safe")

    def test_export_import_round_trip(self):
        snap = self.e.export_brain()
        fresh = naive_bayes.PayloadMonitor()
        fresh.import_brain(snap)
        self.assertEqual(fresh.prior_malicious, self.e.prior_malicious)
        self.assertEqual(set(fresh.likelihoods), set(self.e.likelihoods))


class TestKMeans(unittest.TestCase):
    def test_returns_valid_cluster(self):
        e = kmeans.KMeansMonitor(k=3, learning_rate=0.05)
        self.assertIn(e.classify(10, 2), (0, 1, 2))

    def test_centroid_moves_after_observation(self):
        e = kmeans.KMeansMonitor(k=3, learning_rate=0.5)
        before = list(e.centroids[0])
        e.classify(20, 4)
        self.assertNotEqual(before, e.centroids[0])


class TestBloom(unittest.TestCase):
    def test_added_item_found(self):
        bf = bloom.BloomFilter(size=200, hash_count=3)
        bf.add("10.0.0.5")
        self.assertTrue(bf.check("10.0.0.5"))

    def test_unknown_item_not_found(self):
        bf = bloom.BloomFilter(size=200, hash_count=3)
        bf.add("10.0.0.5")
        self.assertFalse(bf.check("8.8.8.8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

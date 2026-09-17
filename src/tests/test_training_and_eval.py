# tests for the training + evaluation pipelines
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from evaluation import evaluate
from training import loader, train


KNN_CSV = """unique_ports,packet_count,label
1,5,Normal
2,8,Normal
3,12,Normal
50,60,Scan
100,200,Scan
500,1000,Scan
"""

PAYLOAD_CSV = """payload,label
GET /index.html,Normal
GET /about,Normal
GET /home HTTP/1.1,Normal
GET /?id=1 UNION SELECT,Malicious
GET /?u=admin' OR 1=1 --,Malicious
GET /search?q=<SCRIPT>alert(1)</SCRIPT>,Malicious
"""


def _tmp_csv(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
    f.write(text)
    f.close()
    return f.name


class TestLoader(unittest.TestCase):
    def test_knn_loader(self):
        p = _tmp_csv(KNN_CSV)
        try:
            rows = loader.load_knn_csv(p)
            self.assertEqual(len(rows), 6)
            self.assertEqual(rows[0][2], "Normal")
            self.assertEqual(rows[-1][2], "Scan")
        finally:
            os.unlink(p)

    def test_payload_loader(self):
        p = _tmp_csv(PAYLOAD_CSV)
        try:
            rows = loader.load_payload_csv(p)
            self.assertEqual(len(rows), 6)
            self.assertSetEqual({l for _, l in rows},
                                {"Normal", "Malicious"})
        finally:
            os.unlink(p)

        z = _tmp_csv("pps,label\n10,Normal\n9000,DDoS\n")
        b = _tmp_csv("ip,label\n192.0.2.1,Malicious\n192.0.2.2,Normal\n")
        try:
            self.assertEqual(len(loader.load_zscore_csv(z)), 2)
            self.assertEqual(len(loader.load_bloom_csv(b)), 2)
        finally:
            os.unlink(z)
            os.unlink(b)

    def test_missing_columns_raises(self):
        p = _tmp_csv("foo,bar\n1,2\n")
        try:
            with self.assertRaises(loader.DatasetError):
                loader.load_knn_csv(p)
        finally:
            os.unlink(p)

    def test_cic_destination_port_is_not_used_as_unique_port_count(self):
        p = _tmp_csv(
            "Tot Fwd Pkts,Dst Port,Label\n50,0,DDoS\n40,443,Benign\n")
        try:
            with self.assertRaisesRegex(loader.DatasetError,
                                        "pre-aggregated.*unique_ports"):
                loader.load_cic_iot2023(p)
        finally:
            os.unlink(p)

    def test_cic_only_labels_scan_families_as_scan(self):
        p = _tmp_csv(
            "packet_count,unique_ports,label\n"
            "1000,20,DDoS\n40,30,Recon-PortScan\n80,12,Benign\n")
        try:
            rows = loader.load_cic_iot2023(p)["knn"]
            self.assertEqual([row[2] for row in rows],
                             ["Normal", "Scan", "Normal"])
        finally:
            os.unlink(p)


class TestTrain(unittest.TestCase):
    def test_knn_keeps_rows(self):
        rows = [[2, 8, "Normal"], [3, 12, "Normal"],
                [50, 60, "Scan"], [100, 200, "Scan"]]
        b = train.train_knn(rows)
        self.assertEqual(b["k"], 3)
        self.assertEqual(len(b["training_data"]), 4)

    def test_naive_bayes_priors_sum_to_one(self):
        rows = [("GET /", "Normal"), ("GET /home", "Normal"),
                ("UNION SELECT", "Malicious"), ("OR 1=1", "Malicious")]
        b = train.train_naive_bayes(rows)
        self.assertAlmostEqual(b["prior_malicious"] + b["prior_safe"],
                               1.0, places=2)
        self.assertIn("UNION", b["likelihoods"])

    def test_kmeans_returns_k_centroids(self):
        pts = [[10, 2], [12, 3], [200, 5], [250, 6], [20, 50], [25, 60]]
        b = train.train_kmeans(pts, k=3)
        self.assertEqual(b["k"], 3)
        self.assertEqual(len(b["centroids"]), 3)


class TestEvaluate(unittest.TestCase):
    def test_knn_metrics(self):
        p = _tmp_csv(KNN_CSV)
        try:
            r = evaluate.evaluate_knn(loader.load_knn_csv(p), brain={})
            self.assertGreaterEqual(r["accuracy"], 0.8)
            self.assertEqual(r["engine"], "KNN (Port Scan)")
        finally:
            os.unlink(p)

    def test_payload_metrics_have_keys(self):
        p = _tmp_csv(PAYLOAD_CSV)
        try:
            r = evaluate.evaluate_payload(loader.load_payload_csv(p),
                                          brain={})
            for k in ("precision", "recall", "f1", "accuracy",
                      "confusion_matrix"):
                self.assertIn(k, r)
        finally:
            os.unlink(p)

    def test_brain_round_trip(self):
        brain = {
            "knn": train.train_knn(
                [[2, 8, "Normal"], [50, 60, "Scan"]]),
            "z_score": train.train_zscore(
                [(10, "Normal"), (12, "Normal")])[0],
            "bloom": train.train_bloom(
                [("192.0.2.66", "Malicious"),
                 ("192.0.2.1", "Normal")]),
            "_meta": {"trained_at": "test"},
        }
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "mantis_brain.json")
            written = train.write_brain(out, brain)
            self.assertTrue(os.path.isfile(written))
            with open(written) as f:
                restored = json.load(f)
                self.assertIn("knn", restored)
                self.assertIn("z_score", restored)
                self.assertIn("bloom", restored)


if __name__ == "__main__":
    unittest.main(verbosity=2)

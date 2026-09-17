#!/usr/bin/env python3
# trains mantis engines from a csv/json dataset and writes mantis_brain.json
import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from training import loader
from engines.bloom import BloomFilter
from engines.kmeans import KMeansMonitor
from engines.knn import KNNMonitor
from engines.naive_bayes import PayloadMonitor
from engines.z_score import MinimalistStats


KEYWORDS = ["UNION", "SELECT", "SLEEP", "DROP", "INSERT", "UPDATE",
            "OR 1=1", "SCRIPT", "ALERT(", "/ETC/PASSWD"]


def train_knn(rows, max_samples=5000):
    engine = KNNMonitor(k=3)
    engine.train(rows, max_samples=max_samples)
    return engine.export_brain()


def train_naive_bayes(rows, keywords=None, laplace=1.0):
    engine = PayloadMonitor()
    engine.train(rows, laplace=laplace, discover=True)
    if keywords:
        # Retain explicitly requested seed words alongside discovered terms.
        learned = engine.likelihoods
        for word in keywords:
            if word not in learned:
                learned[word] = (0.5, 0.01)
    return engine.export_brain()


def train_kmeans(points, k=3, iters=25):
    engine = KMeansMonitor(k=k)
    engine.train(points, iters=iters)
    return engine.export_brain()


def train_zscore(rows):
    normal = [pps for pps, label in rows if label == "Normal"]
    if not normal:
        raise ValueError("z-score training set must contain normal rows")
    engine = MinimalistStats()
    engine.train(normal)
    return engine.export_brain(), len(normal)


def train_bloom(rows):
    engine = BloomFilter()
    engine.train(rows)
    return engine.export_brain()


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_record(engine, path, rows, retained=None, labels=None):
    return {
        "engine": engine,
        "file": os.path.normpath(path),
        "sha256": _sha256(path),
        "input_rows": int(rows),
        "retained_rows": int(rows if retained is None else retained),
        "class_distribution": dict(Counter(labels or [])),
    }


def write_brain(path, brain):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    base = path[:-5] if path.endswith(".json") else path
    out = "%s_%s.json" % (base, time.strftime("%Y%m%d_%H%M%S"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(brain, f, indent=4)
    print("[+] saved", out)
    return out


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="mantis-train",
                                description="train mantis from a dataset")
    p.add_argument("--knn-csv")
    p.add_argument("--payload-csv")
    p.add_argument("--kmeans-csv")
    p.add_argument("--zscore-csv", help="csv with pps,label; normal rows form baseline")
    p.add_argument("--bloom-csv", help="csv with ip,label; benign rows are ignored")
    p.add_argument("--cic-iot2023", help="CIC-IoT2023 flow csv")
    p.add_argument("--json", dest="json_path",
                   help="combined json file with knn/payload/kmeans keys")
    p.add_argument("--out", default="data/mantis_brain.json")
    p.add_argument("--max-knn-samples", type=int, default=5000)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    brain = {}
    sources = []
    used = 0

    if args.json_path:
        data = loader.load_json(args.json_path)
        json_rows = 0
        json_labels = []
        if "knn" in data:
            brain["knn"] = train_knn(data["knn"], args.max_knn_samples)
            json_rows += len(data["knn"])
            json_labels.extend(row[2] for row in data["knn"])
        if "payload" in data:
            payload_rows = [(r["payload"], r["label"])
                            for r in data["payload"]]
            brain["payload"] = train_naive_bayes(payload_rows)
            json_rows += len(payload_rows)
            json_labels.extend(row[1] for row in payload_rows)
        if "kmeans" in data:
            brain["kmeans"] = train_kmeans(data["kmeans"])
            json_rows += len(data["kmeans"])
        sources.append(source_record(
            "combined_json", args.json_path, json_rows,
            labels=json_labels))
        used += 1

    if args.cic_iot2023:
        cic = loader.load_cic_iot2023(args.cic_iot2023)
        brain["knn"] = train_knn(cic["knn"], args.max_knn_samples)
        brain["kmeans"] = train_kmeans(cic["kmeans"])
        sources.append(source_record(
            "knn+kmeans", args.cic_iot2023, len(cic["knn"]),
            retained=len(brain["knn"]["training_data"]),
            labels=[row[2] for row in cic["knn"]]))
        used += 1

    if args.knn_csv:
        rows = loader.load_knn_csv(args.knn_csv)
        brain["knn"] = train_knn(rows, args.max_knn_samples)
        sources.append(source_record(
            "knn", args.knn_csv, len(rows),
            retained=len(brain["knn"]["training_data"]),
            labels=[row[2] for row in rows]))
        used += 1

    if args.payload_csv:
        rows = loader.load_payload_csv(args.payload_csv)
        brain["payload"] = train_naive_bayes(rows)
        sources.append(source_record(
            "payload", args.payload_csv, len(rows),
            labels=[row[1] for row in rows]))
        used += 1

    if args.kmeans_csv:
        rows = loader.load_kmeans_csv(args.kmeans_csv, include_labels=True)
        normal_points = [point for point, label in rows if label == "Normal"]
        if not normal_points:
            raise loader.DatasetError(
                args.kmeans_csv + ": no Normal rows for K-Means baseline")
        brain["kmeans"] = train_kmeans(normal_points)
        sources.append(source_record(
            "kmeans", args.kmeans_csv, len(rows), retained=len(normal_points),
            labels=[label for _, label in rows]))
        used += 1

    if args.zscore_csv:
        rows = loader.load_zscore_csv(args.zscore_csv)
        brain["z_score"], retained = train_zscore(rows)
        sources.append(source_record(
            "z_score", args.zscore_csv, len(rows), retained=retained,
            labels=[row[1] for row in rows]))
        used += 1

    if args.bloom_csv:
        rows = loader.load_bloom_csv(args.bloom_csv)
        brain["bloom"] = train_bloom(rows)
        sources.append(source_record(
            "bloom", args.bloom_csv, len(rows),
            retained=brain["bloom"]["items_added"],
            labels=[row[1] for row in rows]))
        used += 1

    if used == 0:
        print("[!] no dataset given. try --help")
        return 2

    brain["_meta"] = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engines": sorted(k for k in brain if not k.startswith("_")),
        "sources": sources,
        "note": "Small packaged datasets demonstrate reproducible training; they are not benchmark-scale evidence.",
    }
    write_brain(args.out, brain)
    return 0


if __name__ == "__main__":
    sys.exit(main())

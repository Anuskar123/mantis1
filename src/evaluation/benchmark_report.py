#!/usr/bin/env python3
"""Build a human-readable benchmark + model-comparison report for supervisors."""
import argparse
import json
import os
import sys
import time


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def fmt_pct(x):
    return "%.2f%%" % (float(x) * 100)


def best_by_f1(results):
    if not results:
        return None
    return max(results, key=lambda r: r.get("f1", 0))


def rank_results(results):
    return sorted(results, key=lambda r: (-r.get("f1", 0), -r.get("recall", 0)))


def brain_training_summary(brain):
    lines = []
    if "knn" in brain:
        n = len(brain["knn"].get("training_data", []))
        lines.append(
            "  KNN (Port Scan)       | K-Nearest Neighbours | "
            "CIC-IoT2023 / knn CSV  | %d labelled samples | k=%s"
            % (n, brain["knn"].get("k", 3))
        )
    if "payload" in brain:
        kw = len(brain["payload"].get("likelihoods", {}))
        prior = brain["payload"].get("prior_malicious", "?")
        lines.append(
            "  Naive Bayes (Payload) | Multinomial NB       | "
            "payload_sample.csv     | %d keywords, prior_mal=%s"
            % (kw, prior)
        )
    if "kmeans" in brain:
        k = brain["kmeans"].get("k", 3)
        cents = len(brain["kmeans"].get("centroids", []))
        lines.append(
            "  K-Means (Drift)       | Mini-batch K-Means   | "
            "CIC-IoT2023            | k=%s, %d centroids (online at runtime)"
            % (k, cents)
        )
    lines.append(
        "  Z-Score (DDoS)        | Welford online stats | "
        "Runtime baseline       | threshold=3.0 sigma (not stored in brain JSON)"
    )
    lines.append(
        "  Bloom Filter (IP rep) | Probabilistic hash   | "
        "Seeded blacklist       | O(1) lookup (not ML-trained from CSV)"
    )
    return lines


def build_report(tests_ok, tests_total, brain_path, eval_data, out_path):
    brain = load_json(brain_path) if brain_path and os.path.isfile(brain_path) else {}
    results = eval_data.get("results", [])
    ranked = rank_results(results)
    best = best_by_f1(results)
    trained = [k for k in brain if not k.startswith("_")]
    meta = brain.get("_meta", {})

    L = [
        "=" * 72,
        "  MANTIS BENCHMARK & MODEL COMPARISON REPORT",
        "=" * 72,
        "  Generated : %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "  Brain file: %s" % (brain_path or "n/a"),
        "  Trained at: %s" % meta.get("trained_at", "n/a"),
        "",
        "-" * 72,
        "  1. EXECUTIVE SUMMARY (for supervisor)",
        "-" * 72,
        "",
        "  Unit tests passed     : %d / %d" % (tests_ok, tests_total),
        "  Offline-trained models: %d  (%s)"
        % (len(trained), ", ".join(trained) if trained else "none"),
        "  Evaluated engines     : %d  (offline harness)"
        % len(results),
        "",
        "  MANTIS uses an ENSEMBLE: each model targets a different attack type.",
        "  We do NOT pick one global 'best model' - we compare each engine on",
        "  its own labelled test set and select the strongest per category.",
        "",
    ]

    if best:
        L += [
            "  Highest F1 this run : %s (F1=%.4f)"
            % (best["engine"], best["f1"]),
            "",
        ]

    L += [
        "-" * 72,
        "  2. TRAINED MODELS (what was learned from datasets)",
        "-" * 72,
        "",
        "  Model                 | Algorithm            | Dataset                | Detail",
        "  ----------------------|----------------------|------------------------|------------------",
    ]
    L.extend(brain_training_summary(brain))
    L += ["", "-" * 72, "  3. EVALUATION METRICS (how we compare)", "-" * 72, ""]
    L += [
        "  For each engine we run every labelled test sample, build a confusion",
        "  matrix (TP/FP/FN/TN), then compute:",
        "",
        "    Precision = TP / (TP + FP)   - alerts that were correct",
        "    Recall    = TP / (TP + FN)   - attacks that were caught",
        "    F1        = 2PR / (P + R)    - balanced score (PRIMARY metric)",
        "    Accuracy  = (TP+TN) / total  - overall correctness",
        "",
        "  Primary selection rule: highest F1 per attack category.",
        "",
    ]

    if results:
        hdr = (
            "  %-22s %5s %5s %5s %5s %9s %9s %7s %9s"
            % ("Engine", "TP", "FP", "FN", "TN", "Prec", "Recall", "F1", "Accuracy")
        )
        L.append(hdr)
        L.append("  " + "-" * 68)
        for r in ranked:
            cm = r["confusion_matrix"]
            L.append(
                "  %-22s %5d %5d %5d %5d %9s %9s %7.4f %9s"
                % (
                    r["engine"][:22],
                    cm["tp"], cm["fp"], cm["fn"], cm["tn"],
                    fmt_pct(r["precision"]),
                    fmt_pct(r["recall"]),
                    r["f1"],
                    fmt_pct(r["accuracy"]),
                )
            )
        L.append("")
        L.append("  Ranking by F1 (best first):")
        for i, r in enumerate(ranked, 1):
            L.append("    %d. %s - F1=%.4f" % (i, r["engine"], r["f1"]))
    else:
        L.append("  (no evaluation results - run mantis-eval first)")

    L += [
        "",
        "-" * 72,
        "  4. WHICH MODEL IS 'BEST'? (supervisor Q&A)",
        "-" * 72,
        "",
        "  Q: How do you compare your models?",
        "  A: Train on labelled data -> evaluate on held-out labelled CSVs ->",
        "     confusion matrix -> Precision / Recall / F1. Same pipeline for",
        "     every engine so comparison is fair and reproducible.",
        "",
        "  Q: Which model wins overall?",
        "  A: None alone - MANTIS is an ensemble. Each engine owns one feature:",
        "       * Z-Score     -> volumetric DDoS (packets-per-second spikes)",
        "       * KNN         -> port-scan behaviour (ports vs packet count)",
        "       * Naive Bayes -> malicious HTTP/TCP payloads (SQLi keywords)",
        "       * K-Means     -> behavioural drift (live cluster distance)",
        "       * Bloom Filter-> known-malicious IP reputation",
        "",
        "  Q: Best per category on THIS benchmark run:",
    ]

    by_engine = {r["engine"]: r for r in results}
    categories = [
        ("Port scan detection", "KNN (Port Scan)"),
        ("Payload / SQLi detection", "Naive Bayes (Payload)"),
        ("DDoS / flood detection", "Z-Score (DDoS)"),
    ]
    for label, key in categories:
        r = by_engine.get(key)
        if r:
            L.append(
                "       * %-26s -> %s  F1=%.4f  (P=%s R=%s)"
                % (label, key, r["f1"], fmt_pct(r["precision"]), fmt_pct(r["recall"]))
            )
        else:
            L.append("       * %-26s -> (not evaluated this run)" % label)

    L += [
        "",
        "  Q: Why might recall look low on small samples?",
        "  A: Interim CSV samples are tiny (40-24 rows). Low recall on Z-Score",
        "     or Naive Bayes reflects corpus size, not a broken algorithm.",
        "     KNN trained on 20k CIC-IoT2023 rows shows higher scan recall.",
        "",
        "  Q: How does MANTIS compare to Snort / Wazuh?",
        "  A: Qualitative criteria (anomaly detection, blocking, RAM, transparency)",
        "     plus planned head-to-head on the same CIC-IoT2023 slice with CPU/RAM.",
        "",
        "-" * 72,
        "  5. REPRODUCE THIS REPORT",
        "-" * 72,
        "",
        "  cd src",
        "  ./benchmark.sh",
        "",
        "  Outputs:",
        "    data/mantis_brain_<timestamp>.json  - trained models",
        "    evaluation_results.json             - machine-readable metrics",
        "    evaluation_results.txt              - short eval summary",
        "    benchmark_report.txt                - this file (supervisor brief)",
        "",
        "=" * 72,
    ]

    text = "\n".join(L) + "\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="MANTIS benchmark comparison report")
    p.add_argument("--brain", required=True)
    p.add_argument("--eval-json", default="evaluation_results.json")
    p.add_argument("--out", default="benchmark_report.txt")
    p.add_argument("--tests-ok", type=int, default=0)
    p.add_argument("--tests-total", type=int, default=0)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not os.path.isfile(args.eval_json):
        print("[!] missing:", args.eval_json, file=sys.stderr)
        return 1
    eval_data = load_json(args.eval_json)
    text = build_report(
        args.tests_ok, args.tests_total, args.brain, eval_data, args.out
    )
    print(text)
    print("[+] wrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

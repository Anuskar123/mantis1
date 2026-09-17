#!/usr/bin/env python3
# runs each engine over a labelled dataset and prints TP/FP/precision/recall/f1
import argparse
import csv
import glob
import json
import math
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from engines import bloom as bloom_engine
from engines import kmeans as kmeans_engine
from engines import knn as knn_engine
from engines import naive_bayes as nb_engine
from engines import z_score as zscore_engine
from training import loader


def confusion(y_true, y_pred, positive):
    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if t == positive and p == positive:
            tp += 1
        elif t != positive and p == positive:
            fp += 1
        elif t == positive and p != positive:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def scores(cm):
    """Derive metrics from a confusion matrix, including prevalence-aware ones.

    Precision, recall, F1 and accuracy are all sensitive to class balance, and
    on a corpus dominated by one class they flatter a detector that has learned
    nothing. CIC-IoT2023 is 97.6% attack, so a classifier that simply answers
    "attack" every time scores F1 = 0.9879 there while having no skill at all.
    Reporting only F1 against such a corpus therefore cannot distinguish a
    working engine from a constant function.

    Three additions make the numbers interpretable:

        specificity        - recall on the negative class, which a
                             majority-positive guesser scores 0.0 on
        balanced_accuracy  - mean of recall and specificity, so both classes
                             count equally regardless of prevalence
        mcc                - Matthews correlation coefficient, which uses all
                             four cells and is 0.0 for any constant classifier

    `no_skill_f1` records what the majority-positive baseline would score on
    the same data, so every reported F1 can be read against the number it has
    to beat to mean anything.
    """
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    total = tp + fp + fn + tn
    pr = tp / (tp + fp) if (tp + fp) else 0.0
    rc = tp / (tp + fn) if (tp + fn) else 0.0
    sp = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = (2 * pr * rc / (pr + rc)) if (pr + rc) else 0.0
    acc = (tp + tn) / total if total else 0.0
    bal = (rc + sp) / 2.0

    denom = math.sqrt(float(tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom) if denom else 0.0

    # majority-positive baseline on this same data: predict positive always
    pos = tp + fn
    prevalence = (pos / total) if total else 0.0
    ns_f1 = (2 * prevalence / (prevalence + 1.0)) if prevalence else 0.0

    return {"precision": round(pr, 4), "recall": round(rc, 4),
            "specificity": round(sp, 4), "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "balanced_accuracy": round(bal, 4), "mcc": round(mcc, 4),
            "prevalence": round(prevalence, 4),
            "no_skill_f1": round(ns_f1, 4)}


def load_brain(path):
    """Resolve the brain to evaluate against.

    Passing nothing evaluates the seeded engines, which is the reproducible
    default: silently picking up whichever brain file happened to be newest
    made the same command produce different metrics on different days, and made
    published figures impossible to re-derive. Use `--brain auto` for the old
    behaviour, or name a file explicitly.

    Note that a brain must be evaluated on data drawn from the same feature
    distribution it was trained on. A CIC-IoT2023 brain scored against the
    small hand-built sample CSVs reports meaningless numbers, because the two
    occupy different regions of the feature space.
    """
    if not path:
        print("[*] no --brain given: evaluating seeded engines "
              "(reproducible default)")
        return {}
    if path == "auto":
        candidates = sorted(glob.glob("data/mantis_brain_*.json"))
        if not candidates:
            print("[!] no brain files found in data/")
            return {}
        path = candidates[-1]
        print("[*] using latest brain:", path)
    if not os.path.isfile(path):
        print("[!] brain not found:", path)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        print("[*] evaluating against brain:", path)
        return json.load(f)


def evaluate_knn(rows, brain):
    eng = knn_engine.KNNMonitor(k=brain.get("knn", {}).get("k", 3))
    if "knn" in brain:
        eng.import_brain(brain["knn"])
    yt, yp = [], []
    for ports, pkts, label in rows:
        verdict, _ = eng.classify(ports, pkts)
        yt.append(label)
        yp.append(verdict)
    cm = confusion(yt, yp, "Scan")
    return {"engine": "KNN (Port Scan)", "samples": len(rows),
            "confusion_matrix": cm, **scores(cm)}


def evaluate_payload(rows, brain):
    eng = nb_engine.PayloadMonitor()
    if "payload" in brain:
        eng.import_brain(brain["payload"])
    yt, yp = [], []
    for payload, label in rows:
        verdict, _, _ = eng.classify(payload.encode("utf-8", errors="ignore"))
        yt.append("Malicious" if label in {"Malicious", "Attack"} else "Safe")
        yp.append(verdict)
    cm = confusion(yt, yp, "Malicious")
    return {"engine": "Naive Bayes (Payload)", "samples": len(rows),
            "confusion_matrix": cm, **scores(cm)}


def evaluate_zscore(series, threshold=3.0, window=30, guard_baseline=True):
    """Evaluate the volumetric engine through its uniform analyse() interface.

    `guard_baseline=False` reproduces the naive estimator, which lets the two
    variants be reported side by side (see --compare). The difference is large:
    without the guard a sustained flood is absorbed into the rolling baseline
    within `window` seconds and recall collapses.
    """
    eng = zscore_engine.MinimalistStats(window_size=window,
                                        threshold=threshold,
                                        guard_baseline=guard_baseline)
    yt, yp = [], []
    for pps, label in series:
        verdict = eng.analyse(pps)
        yp.append("DDoS" if verdict.is_threat else "Normal")
        yt.append("DDoS" if label in {"DDoS", "Attack", "Malicious"} else "Normal")
    cm = confusion(yt, yp, "DDoS")
    name = "Z-Score (DDoS)" if guard_baseline else "Z-Score (DDoS, naive baseline)"
    return {"engine": name, "samples": len(series),
            "threshold": threshold, "window": window,
            "guard_baseline": guard_baseline,
            "confusion_matrix": cm, **scores(cm)}


def evaluate_kmeans(series, brain, k=3, alpha=0.05, radius_multiplier=3.0):
    """Evaluate the clustering engine as a novelty detector.

    Chapter 6 previously reported no K-Means figures at all, while Chapter
    6.3.2 relied on the engine to supplement the ensemble. Because the engine
    now decides on distance from the learned centroids rather than on cluster
    identity, it produces a binary verdict that can be scored like the others.
    """
    eng = kmeans_engine.KMeansMonitor(k=k, learning_rate=alpha,
                                     radius_multiplier=radius_multiplier)
    if "kmeans" in brain:
        eng.import_brain(brain["kmeans"])
    yt, yp = [], []
    for pps, ports, label in series:
        verdict = eng.analyse(pps, ports)
        yp.append("Anomaly" if verdict.is_threat else "Normal")
        yt.append("Anomaly" if label in {"Anomaly", "Attack", "Malicious",
                                        "DDoS", "Scan"} else "Normal")
    cm = confusion(yt, yp, "Anomaly")
    return {"engine": "K-Means (Novelty)", "samples": len(series),
            "radius_multiplier": radius_multiplier,
            "confusion_matrix": cm, **scores(cm)}


def evaluate_bloom(rows, size=1000, hashes=3, train_split=0.5):
    """Evaluate the reputation filter, and measure its false-positive rate.

    Bloom filters cannot produce false negatives, so recall on the indicators
    actually loaded is 1.0 by construction. The figure worth reporting is the
    empirical false-positive rate on addresses that were never inserted, which
    is what the bit-array sizing trades against memory. Both are reported here.
    """
    malicious = [ip for ip, label in rows
                 if label in {"Malicious", "Attack", "Blacklisted"}]
    benign = [ip for ip, label in rows if ip not in set(malicious)]

    split = max(1, int(len(malicious) * train_split))
    loaded, held_out = malicious[:split], malicious[split:]

    eng = bloom_engine.BloomFilter(size=size, hash_count=hashes)
    for ip in loaded:
        eng.add(ip)

    yt, yp = [], []
    for ip in loaded:
        yt.append("Blacklisted")
        yp.append("Blacklisted" if eng.check(ip) else "Unknown")
    for ip in benign:
        yt.append("Unknown")
        yp.append("Blacklisted" if eng.check(ip) else "Unknown")

    cm = confusion(yt, yp, "Blacklisted")
    result = {"engine": "Bloom Filter (Reputation)",
              "samples": len(loaded) + len(benign),
              "indicators_loaded": len(loaded),
              "bit_array_size": size, "hash_count": hashes,
              "saturation": round(eng.saturation(), 4),
              "theoretical_fp_rate": round(eng.false_positive_rate(), 6),
              "confusion_matrix": cm, **scores(cm)}
    if held_out:
        # indicators never inserted must not be recognised
        leaked = sum(1 for ip in held_out if eng.check(ip))
        result["held_out_indicators"] = len(held_out)
        result["held_out_false_hits"] = leaked
    return result


def print_report(results):
    L = ["",
         "================================================================",
         "  MANTIS Evaluation Report",
         "================================================================",
         "  " + time.strftime("%Y-%m-%d %H:%M:%S"), ""]
    for r in results:
        cm = r["confusion_matrix"]
        L += [
            "--- %s ---" % r["engine"],
            "  Samples         : %d" % r["samples"],
            "  True  Positives : %d" % cm["tp"],
            "  False Positives : %d" % cm["fp"],
            "  False Negatives : %d" % cm["fn"],
            "  True  Negatives : %d" % cm["tn"],
            "  Precision       : %.4f" % r["precision"],
            "  Recall          : %.4f" % r["recall"],
            "  Specificity     : %.4f" % r.get("specificity", 0.0),
            "  F1              : %.4f" % r["f1"],
            "  Accuracy        : %.4f" % r["accuracy"],
            "  Balanced Acc.   : %.4f" % r.get("balanced_accuracy", 0.0),
            "  MCC             : %.4f" % r.get("mcc", 0.0),
            "  Prevalence      : %.4f (positive-class share of this data)"
            % r.get("prevalence", 0.0),
            "  No-skill F1     : %.4f (majority-positive guesser scores this)"
            % r.get("no_skill_f1", 0.0),
        ]
        if r["f1"] <= r.get("no_skill_f1", 0.0):
            L.append("  [!] F1 does NOT beat the no-skill baseline on this "
                     "data - read MCC / balanced accuracy instead.")
        L.append("")
    # cross-engine summary so all engines appear in one comparable table
    if len(results) > 1:
        L += ["--- Summary ---",
              "  %-34s %9s %8s %8s %8s %8s" % ("Engine", "Precision",
                                               "Recall", "F1", "Bal.Acc",
                                               "MCC"),
              "  " + "-" * 78]
        for r in results:
            L.append("  %-34s %9.4f %8.4f %8.4f %8.4f %8.4f"
                     % (r["engine"][:34], r["precision"], r["recall"],
                        r["f1"], r.get("balanced_accuracy", 0.0),
                        r.get("mcc", 0.0)))
        L.append("")

    L.append("================================================================")
    text = "\n".join(L)
    print(text)
    return text


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="mantis-eval",
                                description="evaluate mantis engines")
    p.add_argument("--knn-csv")
    p.add_argument("--payload-csv")
    p.add_argument("--zscore-csv", help="csv with pps,label")
    p.add_argument("--cic-zscore-csv",
                   help="CIC-IoT2023 export; evaluates the volumetric engine "
                        "on its Rate/Label columns")
    p.add_argument("--cic-limit", type=int,
                   help="cap rows read from --cic-zscore-csv")
    p.add_argument("--cic-benign-ratio", type=float,
                   help="also evaluate --cic-zscore-csv resampled to this "
                        "benign prevalence (e.g. 0.95), testing whether the "
                        "recall collapse is caused by class imbalance")
    p.add_argument("--kmeans-csv",
                   help="csv with pps,unique_ports,label")
    p.add_argument("--bloom-csv", help="csv with ip,label")
    p.add_argument("--brain",
                   help="brain json to evaluate against, or 'auto' for the "
                        "newest in data/ (default: seeded engines)")
    p.add_argument("--out-json", default="evaluation_results.json")
    p.add_argument("--out-txt", default="evaluation_results.txt")
    p.add_argument("--zscore-threshold", type=float, default=3.0)
    p.add_argument("--zscore-window", type=int, default=30)
    p.add_argument("--compare", action="store_true",
                   help="also evaluate the naive Z-Score baseline for "
                        "side-by-side comparison")
    return p.parse_args(argv)


def load_zscore_csv(path):
    series = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        h = {c.lower().strip(): c for c in (r.fieldnames or [])}
        if "pps" not in h or "label" not in h:
            raise loader.DatasetError(path + ": need pps,label cols")
        for row in r:
            series.append((int(float(row[h["pps"]])), row[h["label"]]))
    return series


def load_cic_zscore_csv(path, limit=None):
    """Derive a packets-per-second series from a CIC-IoT2023 flow export.

    The benchmark ships one row per flow with a `Rate` column (packets per
    second observed for that flow) and a `Label` naming the attack class.
    Feeding `Rate` to the volumetric engine is how the interim evaluation
    produced its Z-Score figures, so loading it here keeps the corrected
    engine directly comparable against that published baseline.

    One caveat is worth stating plainly, because it bounds what the resulting
    metrics mean: flow records are not a true temporal series. Row order is
    the order of the export, not wall-clock arrival order, so the engine sees
    a sequence of rate observations rather than genuine per-second traffic.
    That approximation is acceptable for a like-for-like comparison against
    the interim figure -- both variants see identical input in identical
    order -- but it is not a substitute for the live-capture and PCAP replay
    evaluations, where ordering is real.
    """
    series = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        h = {c.lower().strip(): c for c in (r.fieldnames or [])}
        if "rate" not in h or "label" not in h:
            raise loader.DatasetError(path + ": need Rate,Label cols")
        for row in r:
            try:
                rate = float(row[h["rate"]])
            except (TypeError, ValueError):
                continue
            if rate != rate or rate in (float("inf"), float("-inf")):
                continue  # skip NaN/inf rows rather than poisoning the baseline
            label = (row[h["label"]] or "").strip().upper()
            series.append((int(rate), "Normal" if label == "BENIGN" else "DDoS"))
            if limit and len(series) >= limit:
                break
    return series


def rebalance_series(series, benign_ratio=0.95, warmup=30, seed=1):
    """Rebuild a series at a realistic benign prevalence, benign-first.

    A Z-Score detector rests on one assumption: that the bulk of observed
    traffic is normal, so the running mean approximates normality. The
    CIC-IoT2023 export violates that assumption outright -- only ~2.4% of its
    rows are BENIGN -- so the learned baseline is an attack-level rate and
    almost nothing deviates from it. That is a property of the corpus, not of
    the estimator.

    This helper tests that explanation instead of merely asserting it. The
    majority class is *downsampled* rather than the minority upsampled: every
    benign row is used exactly once and attack rows are drawn without
    replacement until the stated benign prevalence is reached. Upsampling the
    7,173 benign rows to a 95% majority would require recycling each of them
    several hundred times, and the resulting duplicate-driven variance
    collapse would itself distort the standard deviation the estimator
    depends on -- an artefact of the experiment rather than a property of the
    engine.

    A benign warm-up prefix is prepended so a baseline can form, mirroring a
    sensor started on a quiet network, and the remainder is shuffled so
    attacks appear as sporadic bursts within a normal stream. If the recall
    collapse were a defect of the estimator it would persist here, so this is
    a falsifiable test rather than a flattering resample.
    """
    rng = random.Random(seed)
    benign = [s for s in series if s[1] == "Normal"]
    attack = [s for s in series if s[1] != "Normal"]
    if not benign or not attack:
        return list(series)

    keep = int(len(benign) * (1.0 - benign_ratio) / max(1e-9, benign_ratio))
    keep = max(1, min(len(attack), keep))
    sampled_attack = rng.sample(attack, keep)

    out = list(benign[:warmup])
    mixed = list(benign) + sampled_attack
    rng.shuffle(mixed)
    out.extend(mixed)
    return out


def load_kmeans_csv(path):
    """Read pps,ports,label rows for novelty-detection evaluation."""
    series = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        h = {c.lower().strip(): c for c in (r.fieldnames or [])}
        ports_key = "ports" if "ports" in h else "unique_ports"
        if "pps" not in h or ports_key not in h or "label" not in h:
            raise loader.DatasetError(path + ": need pps,ports,label cols")
        for row in r:
            series.append((int(float(row[h["pps"]])),
                           int(float(row[h[ports_key]])),
                           row[h["label"]]))
    return series


def load_bloom_csv(path):
    """Read ip,label rows for reputation-filter evaluation."""
    rows = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        h = {c.lower().strip(): c for c in (r.fieldnames or [])}
        ip_key = "ip" if "ip" in h else "src_ip"
        if ip_key not in h or "label" not in h:
            raise loader.DatasetError(path + ": need ip,label cols")
        for row in r:
            rows.append((row[h[ip_key]].strip(), row[h["label"]].strip()))
    return rows


def main(argv=None):
    args = parse_args(argv)
    brain = load_brain(args.brain)
    out = []

    if args.knn_csv:
        out.append(evaluate_knn(loader.load_knn_csv(args.knn_csv), brain))
    if args.payload_csv:
        out.append(evaluate_payload(
            loader.load_payload_csv(args.payload_csv), brain))
    if args.zscore_csv:
        series = load_zscore_csv(args.zscore_csv)
        out.append(evaluate_zscore(series, args.zscore_threshold,
                                   args.zscore_window, guard_baseline=True))
        if args.compare:
            out.append(evaluate_zscore(series, args.zscore_threshold,
                                       args.zscore_window,
                                       guard_baseline=False))

    if args.cic_zscore_csv:
        series = load_cic_zscore_csv(args.cic_zscore_csv, args.cic_limit)
        guarded = evaluate_zscore(series, args.zscore_threshold,
                                  args.zscore_window, guard_baseline=True)
        guarded["engine"] = "Z-Score (CIC-IoT2023)"
        out.append(guarded)
        if args.compare:
            naive = evaluate_zscore(series, args.zscore_threshold,
                                    args.zscore_window, guard_baseline=False)
            naive["engine"] = "Z-Score (CIC-IoT2023, naive baseline)"
            out.append(naive)
        if args.cic_benign_ratio:
            bal = rebalance_series(series, args.cic_benign_ratio,
                                   warmup=args.zscore_window)
            pct = int(round(args.cic_benign_ratio * 100))
            res = evaluate_zscore(bal, args.zscore_threshold,
                                  args.zscore_window, guard_baseline=True)
            res["engine"] = "Z-Score (CIC-IoT2023, %d%% benign)" % pct
            out.append(res)
            if args.compare:
                res_n = evaluate_zscore(bal, args.zscore_threshold,
                                        args.zscore_window,
                                        guard_baseline=False)
                res_n["engine"] = ("Z-Score (CIC, %d%% benign, naive)" % pct)
                out.append(res_n)

    if args.kmeans_csv:
        out.append(evaluate_kmeans(load_kmeans_csv(args.kmeans_csv), brain))

    if args.bloom_csv:
        out.append(evaluate_bloom(load_bloom_csv(args.bloom_csv)))

    if not out:
        print("[!] no dataset given. try --help")
        return 2

    text = print_report(out)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "results": out}, f, indent=2)
    with open(args.out_txt, "w", encoding="utf-8") as f:
        f.write(text)
    print("[+] wrote", args.out_json, "and", args.out_txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())

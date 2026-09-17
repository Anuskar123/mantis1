#!/usr/bin/env python3
"""MANTIS sensor node: raw capture, engine fan-out, response.

Architecture (Chapter 4.1.2, producer/consumer threading model):

    sniffer thread   AF_PACKET raw socket -> bounded queue
    analyzer thread  queue -> PacketParser -> 5 engines -> AlertDispatcher

The queue decouples the two so that machine-learning work in the analyzer
cannot slow the socket drain, which is what previously caused packet loss
under load (bug B-01). On overflow the sniffer drops rather than blocks, so
capture rate degrades gracefully instead of stalling the kernel buffer.

Per-packet engines (Bloom reputation, Naive Bayes payload) run on every frame.
Per-interval engines (Z-Score volume, KNN port spread, K-Means novelty) run
once per second on aggregated counters, because their features are rates.
"""

import glob
import json
import os
import queue
import socket
import sys
import threading
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard_ui.reporting as reporting
import engines.bloom as bloom
import engines.kmeans as kmeans
import engines.knn as knn
import engines.naive_bayes as naive_bayes
import engines.z_score as z_score
import sensor_node.dispatcher as dispatcher_mod
import sensor_node.parser as parser_mod
import utils.active_defense as active_defense
import utils.logger as logger_mod
import utils.packet_store as packet_store
import utils.pcap as pcap
import utils.privacy as privacy
from utils.config import CONFIG


class SensorNode:
    def __init__(self, stats_queue=None, alert_queue=None,
                 brain_file=None, config=None, forward_alerts=False):
        self.config = config or CONFIG
        self.stats_queue = stats_queue
        self.alert_queue = alert_queue
        self.brain_file = brain_file or self.config.brain_file
        self._shutdown_lock = threading.Lock()
        self._shutdown_complete = False

        self.packet_queue = queue.Queue(maxsize=self.config.queue_size)

        # ---- detection engines (all share the DetectionEngine interface) ----
        self.stats_engine = z_score.MinimalistStats(
            window_size=self.config.zscore_window,
            threshold=self.config.zscore_threshold,
            min_pps=self.config.ddos_min_pps,
            required_consecutive=self.config.ddos_consecutive_intervals)
        self.knn_engine = knn.KNNMonitor(k=self.config.knn_k)
        self.payload_engine = naive_bayes.PayloadMonitor(
            confidence_threshold=self.config.payload_confidence)
        self.kmeans_engine = kmeans.KMeansMonitor(
            k=self.config.kmeans_k, learning_rate=self.config.kmeans_alpha)
        self.blacklist = bloom.BloomFilter(size=self.config.bloom_size,
                                           hash_count=self.config.bloom_hashes)

        self.parser = parser_mod.PacketParser()
        self.reporter = reporting.ReportGenerator()
        self.ips = active_defense.ActiveDefense(
            whitelist=self.config.block_whitelist)

        self.audit_log = logger_mod.Logger(self.config.log_file,
                                           config=self.config)
        self.remote = None
        if forward_alerts:
            self.remote = logger_mod.UDPSender(self.config.udp_host,
                                               self.config.udp_port,
                                               config=self.config)

        self.dispatcher = dispatcher_mod.AlertDispatcher(
            self.config, reporter=self.reporter, alert_queue=alert_queue,
            logger=self.audit_log, remote=self.remote, defense=self.ips)

        # optional live pcap capture, verifiable in Wireshark
        self.pcap_writer = None
        if self.config.pcap_file:
            try:
                self.pcap_writer = pcap.PcapWriter(
                    self.config.pcap_file, snaplen=self.config.pcap_snaplen)
                print("[*] writing capture to %s (snaplen %d)"
                      % (self.config.pcap_file, self.config.pcap_snaplen))
            except OSError as e:
                print("[!] could not open pcap file:", e)

        packet_store.STORE = packet_store.PacketStore(
            maxlen=self.config.packet_buffer)

        self.import_brain_state()

        # An explicitly configured feed is authoritative for this run.  Load
        # it after brain restoration so an older persisted Bloom state cannot
        # silently replace the current operator-supplied indicator file.
        if self.config.blacklist_file:
            self.blacklist.reset()
            if self.blacklist.load_feed(self.config.blacklist_file) <= 0:
                self._seed_blacklist()
        elif self.blacklist.items_added <= 0:
            self._seed_blacklist()

        self.packet_count = 0
        self.unique_ports = set()
        self.source_stats = {}
        self.scan_active_sources = set()
        self.last_time = time.time()
        self.is_running = True
        self.dropped = 0
        self.started_at = time.time()

    def _seed_blacklist(self):
        for ip in ("192.168.1.200", "10.0.0.66"):
            self.blacklist.add(ip)

    # ---- capture -------------------------------------------------------
    def _sniffer_thread(self):
        # pull packets off the wire as fast as possible, drop on overflow
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.ntohs(0x0003))
        except PermissionError:
            print("[!] need sudo for raw sockets")
            self.is_running = False
            return
        except AttributeError:
            print("[!] AF_PACKET unavailable (Linux only). "
                  "Use replay.py for offline analysis on this platform.")
            self.is_running = False
            return

        print("[*] sniffer up")
        while self.is_running:
            try:
                raw, _ = s.recvfrom(65535)
                try:
                    self.packet_queue.put_nowait(raw)
                except queue.Full:
                    self.dropped += 1  # analyzer is too slow - drop
            except Exception as e:
                if self.is_running:
                    print("[!] sniffer error:", e)

    # ---- analysis ------------------------------------------------------
    def _analyzer_thread(self):
        print("[*] analyzer up - 5 engines, dispatcher armed")
        while self.is_running:
            try:
                raw = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                self._run_timer_checks()
                continue

            self._run_timer_checks()

            if self.pcap_writer is not None:
                try:
                    self.pcap_writer.write(raw)
                except Exception:
                    pass  # never let forensics break detection

            pkt = self.parser.parse(raw)
            if pkt is None:
                continue

            # ignore our own dashboard traffic so the sensor cannot alert on
            # the analyst watching it (self-noise feedback loop)
            if (pkt["sport"] in (self.config.http_port, self.config.udp_port)
                    or pkt["dport"] in (self.config.http_port,
                                        self.config.udp_port)):
                continue

            # Interval counters must describe the same successfully parsed,
            # in-scope traffic. Counting every raw Ethernet frame here used to
            # produce impossible observations such as PPS > 0 with zero ports.
            self.packet_count += 1
            src = pkt["src"]
            source_observation = self.source_stats.setdefault(
                src, {"packets": 0, "ports": set()})
            source_observation["packets"] += 1

            # --- Bloom Filter: IP reputation, O(k) per packet ---
            rep = self.blacklist.analyse(src)
            if rep.is_threat:
                self.dispatcher.dispatch(
                    "BLACKLISTED IP DETECTED: %s" % src,
                    kind="blacklist", src_ip=src, confidence=rep.confidence,
                    engine="Bloom Filter (reputation)",
                    response_status=True)
                self._record_packet(raw, pkt, "BLACKLIST")
                continue

            if pkt["dport"]:
                self.unique_ports.add(pkt["dport"])
                source_observation["ports"].add(pkt["dport"])

            # --- Naive Bayes: Layer 7 payload inspection ---
            verdict_tag = "clean"
            if pkt["payload"]:
                verdict = self.payload_engine.analyse(pkt["payload"])
                if verdict.is_threat:
                    verdict_tag = "MALICIOUS"
                    self.dispatcher.dispatch(
                        "MALICIOUS PAYLOAD! Confidence: %.2f%% Keywords: %s"
                        % (verdict.confidence * 100,
                           verdict.detail["keywords"]),
                        src_ip=src, confidence=verdict.confidence,
                        payload=pkt["payload"],
                        engine="Naive Bayes (payload)")

            self._record_packet(raw, pkt, verdict_tag)

    def _run_timer_checks(self):
        now = time.time()
        if (now - self.last_time) < 1.0:
            return

        pps = self.packet_count
        ports = len(self.unique_ports)
        source_stats = self.source_stats
        dominant_src = self._dominant_source(source_stats, pps)

        # --- Z-Score: volumetric flood ---
        zv = self.stats_engine.analyse(pps)
        mean = zv.detail["mean"]
        z = zv.detail["z_score"]
        # Dispatch once when a sustained DDoS episode begins. The active flag
        # remains true for dashboard status without flooding the event stream
        # with a duplicate alert every second.
        if zv.detail["new_threat"]:
            self.dispatcher.dispatch(
                "DDoS DETECTED! Z-Score: %.2f (PPS: %d)" % (z, pps),
                kind="ddos", src_ip=dominant_src, confidence=zv.confidence,
                engine="Z-Score (statistical)")

        # --- KNN: per-source port-scan behaviour ---
        current_scan_sources = set()
        for src, observation in source_stats.items():
            src_packets = observation["packets"]
            src_ports = len(observation["ports"])
            kv = self.knn_engine.analyse(src_ports, src_packets)
            if kv.is_threat:
                current_scan_sources.add(src)
                if src not in self.scan_active_sources:
                    self.dispatcher.dispatch(
                        "PORT SCAN DETECTED! (Unique Ports: %d/sec)"
                        % src_ports,
                        kind="scan", src_ip=src, confidence=kv.confidence,
                        engine="KNN (behavioural)")
        self.scan_active_sources = current_scan_sources

        # --- K-Means: novelty / behavioural drift ---
        cv = self.kmeans_engine.analyse(pps, ports)
        if cv.is_threat and not current_scan_sources and not zv.is_threat:
            self.dispatcher.dispatch(
                "ANOMALY DETECTED (Cluster %d)! Suspicious activity."
                % cv.detail["cluster"], kind="anomaly",
                src_ip=dominant_src, confidence=cv.confidence,
                engine="K-Means (clustering)")

        packet_store.STORE.update_stats(
            pps, mean, z,
            ddos_candidate=zv.detail["volume_candidate"],
            ddos_active=zv.is_threat)
        if self.stats_queue:
            self.stats_queue.put({
                "pps": pps,
                "mean": mean,
                "z_score": z,
                "ddos_candidate": zv.detail["volume_candidate"],
                "ddos_active": zv.is_threat,
            })

        self.packet_count = 0
        self.unique_ports.clear()
        self.source_stats = {}
        self.last_time = now

    def _dominant_source(self, source_stats, total_packets):
        """Return a safely attributable source for an interval alert.

        Aggregate rate/cluster detections cannot honestly name an address when
        traffic is distributed. Only return the highest-volume source when it
        meets the configured dominance threshold; a missing source prevents
        the dispatcher from attempting an unsafe firewall block.
        """
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

    def _record_packet(self, raw, pkt, verdict):
        """Store a bounded snapshot in the in-memory ring buffer.

        The snapshot honours the pcap snaplen, so when privacy mode limits the
        capture to headers the UI hex view shows exactly what was captured and
        nothing more.
        """
        snap_len = max(64, min(128, self.config.pcap_snaplen))
        packet_store.STORE.add({
            "ts": time.time(),
            "time": packet_store.now_hms(),
            "src": pkt["src"],
            "dst": pkt["dst"],
            "proto": pkt["proto"],
            "sport": pkt["sport"],
            "dport": pkt["dport"],
            "length": pkt["length"],
            "info": pkt["info"],
            "verdict": verdict,
            "hex": raw[:snap_len].hex(),
        })

    # ---- lifecycle -----------------------------------------------------
    def start(self):
        print("[*] starting mantis sensor")
        print(self.config.summary())
        threading.Thread(target=self._sniffer_thread, daemon=True).start()
        threading.Thread(target=self._analyzer_thread, daemon=True).start()
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        self.shutdown()

    def shutdown(self):
        with self._shutdown_lock:
            if self._shutdown_complete:
                return False
            self._shutdown_complete = True
            print("\n[!] stopping")
            self.is_running = False
            if self.pcap_writer is not None:
                self.pcap_writer.close()
                print("[*] capture saved: %s (%d packets) - open it in Wireshark"
                      % (self.config.pcap_file, self.pcap_writer.count))
            self.export_brain_state()
            self.reporter.generate()
            self.print_session_summary()
            return True

    def print_session_summary(self):
        uptime = time.time() - self.started_at
        stats = self.parser.stats()
        summary = self.dispatcher.summary()
        print("\n--- session summary ---")
        print("  uptime          : %.1f s" % uptime)
        print("  frames decoded  : %d (non-IPv4 %d, malformed %d)"
              % (stats["parsed"], stats["non_ipv4"], stats["malformed"]))
        print("  queue drops     : %d" % self.dropped)
        print("  alerts raised   : %d %s"
              % (summary["alerts"], summary["by_kind"]))
        print("  IPs blocked     : %s" % (summary["blocked_ips"] or "none"))
        print("  audit log rows  : %d -> %s"
              % (self.audit_log.rows_written, self.config.log_file))

    def export_brain_state(self):
        # save what each engine learned, timestamped so we keep history
        os.makedirs(os.path.dirname(self.brain_file) or ".", exist_ok=True)
        base = self.brain_file.replace(".json", "")
        out = "%s_%s.json" % (base, time.strftime("%Y%m%d_%H%M%S"))
        try:
            with open(out, "w") as f:
                json.dump({
                    "knn": self.knn_engine.export_brain(),
                    "kmeans": self.kmeans_engine.export_brain(),
                    "payload": self.payload_engine.export_brain(),
                    "z_score": self.stats_engine.export_brain(),
                    "bloom": self.blacklist.export_brain(),
                }, f, indent=4)
            print("[*] brain saved to", out)
        except Exception as e:
            print("[!] failed to save brain:", e)

    def import_brain_state(self):
        # auto-load the newest saved brain on boot
        base = self.brain_file.replace(".json", "")
        files = glob.glob("%s_*.json" % base)
        if not files:
            return
        latest = sorted(files)[-1]
        print("[*] loading brain", latest)
        try:
            with open(latest) as f:
                data = json.load(f)
            for key, engine in (("knn", self.knn_engine),
                                ("kmeans", self.kmeans_engine),
                                ("payload", self.payload_engine),
                                ("z_score", self.stats_engine),
                                ("bloom", self.blacklist)):
                if key in data:
                    engine.import_brain(data[key])
        except Exception as e:
            print("[!] failed to load brain:", e)


def start_sensor(stats_queue=None, alert_queue=None, brain_file=None,
                 config=None, forward_alerts=False):
    SensorNode(stats_queue, alert_queue, brain_file, config,
               forward_alerts).start()


if __name__ == "__main__":
    start_sensor()

#!/usr/bin/env python3
"""Central runtime configuration for MANTIS.

Implements NFR-3, which requires that active firewall blocking remains
"strictly opt-in via configuration flags", and NFR-4/NFR-7 which require a
single configurable entry point that is portable across hosts.

Every tunable that used to be a magic number inside an engine or the sensor
is declared here, so a marker can see (and change) the detection thresholds
without reading the source. Settings resolve in this order, later wins:

    1. defaults below
    2. JSON file  (--config mantis.conf.json)
    3. environment variables (MANTIS_*)
    4. command line flags

Standard library only.
"""

import json
import os


class Config:
    def __init__(self):
        # --- capture ---
        self.interface = "any"          # informational; AF_PACKET binds all
        self.packet_buffer = 5000       # in-memory ring buffer size
        self.queue_size = 100000        # sniffer -> analyzer bounded queue

        # --- engine thresholds (were hard-coded before) ---
        self.zscore_window = 30
        self.zscore_threshold = 3.0
        self.ddos_min_pps = 500
        self.ddos_consecutive_intervals = 3
        self.knn_k = 3
        self.kmeans_k = 3
        self.kmeans_alpha = 0.05
        self.payload_confidence = 0.80
        self.alert_dedup_seconds = 5.0
        # Interval detections may only name/block a source when one address
        # accounts for at least this share of the observed packets.
        self.source_attribution_min_share = 0.50

        # --- NFR-3: active defence is OPT-IN, never on by default ---
        self.block_enabled = False
        self.block_whitelist = ["127.0.0.1", "0.0.0.0"]
        # which engines are allowed to trigger a firewall drop
        self.block_on = ["payload", "blacklist", "ddos", "scan"]

        # --- NFR-3 / GDPR + DPA 2018 ---
        self.payload_excerpt_bytes = 64   # truncate stored payload excerpts
        self.privacy_mode = True          # redact PII + anonymise IPs in logs
        self.anonymise_ips = False        # mask last octet in persisted logs

        # --- telemetry ---
        self.udp_host = "127.0.0.1"
        self.udp_port = 9999
        self.http_port = 8080

        # --- threat intelligence ---
        self.blacklist_file = None        # newline separated IP feed
        self.bloom_size = 1000
        self.bloom_hashes = 3

        # --- forensics ---
        self.pcap_file = None             # if set, write a live libpcap capture
        self.pcap_snaplen = 96            # headers only by default (privacy)

        self.brain_file = "data/mantis_brain.json"
        self.log_file = "mantis_logs.csv"

    # ---- loading -------------------------------------------------------
    def load_file(self, path):
        if not path or not os.path.isfile(path):
            return False
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.update(data)
        print("[*] config loaded from %s" % path)
        return True

    def load_env(self, environ=None):
        """Read MANTIS_* environment variables (MANTIS_BLOCK_ENABLED=1)."""
        environ = environ if environ is not None else os.environ
        for key in vars(self):
            env_key = "MANTIS_" + key.upper()
            if env_key in environ:
                self._set_coerced(key, environ[env_key])

    def update(self, data):
        if not isinstance(data, dict):
            return
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def _set_coerced(self, key, raw):
        """Coerce a string (env var / CLI) to the type of the default."""
        current = getattr(self, key)
        try:
            if isinstance(current, bool):
                setattr(self, key, str(raw).strip().lower()
                        in ("1", "true", "yes", "on"))
            elif isinstance(current, int):
                setattr(self, key, int(raw))
            elif isinstance(current, float):
                setattr(self, key, float(raw))
            elif isinstance(current, list):
                setattr(self, key, [p.strip() for p in str(raw).split(",")
                                    if p.strip()])
            else:
                setattr(self, key, raw)
        except (TypeError, ValueError):
            print("[!] ignoring bad config value for %s: %r" % (key, raw))

    def apply_args(self, args):
        """Apply parsed argparse values (None means 'not supplied')."""
        for key, value in vars(args).items():
            if value is None:
                continue
            if hasattr(self, key):
                setattr(self, key, value)

    def as_dict(self):
        return dict(vars(self))

    def summary(self):
        """Short human-readable banner used at sensor start-up."""
        return "\n".join([
            "  interface        : %s" % self.interface,
            "  packet buffer    : %d packets (in-memory)" % self.packet_buffer,
            "  z-score / DDoS   : window=%d threshold=%.1f min_pps=%d "
            "consecutive=%d"
            % (self.zscore_window, self.zscore_threshold, self.ddos_min_pps,
               self.ddos_consecutive_intervals),
            "  knn / kmeans     : k=%d / k=%d alpha=%.2f"
            % (self.knn_k, self.kmeans_k, self.kmeans_alpha),
            "  source attribution: minimum %.0f%% dominant traffic share"
            % (self.source_attribution_min_share * 100),
            "  active defence   : %s%s" % (
                "ENABLED" if self.block_enabled else "disabled (opt-in)",
                (" on " + ",".join(self.block_on)) if self.block_enabled else ""),
            "  privacy mode     : %s (payload excerpt %d bytes)" % (
                "on" if self.privacy_mode else "off",
                self.payload_excerpt_bytes),
            "  pcap capture     : %s" % (self.pcap_file or "off"),
            "  threat intel     : %s" % (self.blacklist_file or "built-in seed"),
        ])


# module-level singleton shared by every component
CONFIG = Config()

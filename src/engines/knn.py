import math
from collections import Counter

try:
    from engines.base import DetectionEngine, Verdict
except ImportError:  # allow `python engines/knn.py` direct execution
    from base import DetectionEngine, Verdict


class KNNMonitor(DetectionEngine):
    """K-nearest neighbours classifier for port-scan versus normal traffic.

    Features per one-second interval:

        0. unique destination ports
        1. packet count
        2. ports / packets  (derived)

    Feature 2 is engineered rather than measured, and it is what makes the two
    classes linearly separable. The first two features overlap badly at the
    decision boundary - 27 ports over 160 packets is ordinary browsing while
    30 ports over 40 packets is a scan, and no threshold on either raw axis
    separates them. Their ratio does, because it encodes the protocol
    behaviour directly: a scanner sends about one SYN per port and never
    completes a handshake, so its ratio approaches 1, whereas a real client
    exchanges many packets over a handful of ports and its ratio stays low.

    The ratio is derived at classification time, so stored training data and
    previously saved brain files keep the original [ports, packets, label]
    shape and remain loadable.
    """

    name = "knn"
    features = ("unique_ports", "packet_count", "ports_per_packet")
    MIN_SCAN_PORTS = 10
    MIN_SCAN_RATIO = 0.20

    def __init__(self, k=3):
        self.k = k
        self.training_data = []

        # Seed data so we work on first boot. Modern sites can hit
        # 10-15 ports easily because of CDNs/ads, so don't go lower.
        #
        # The final four rows cover high-volume / low-port-diversity traffic.
        # They are labelled Normal because this engine answers exactly one
        # question - "is this a port scan?" - and a volumetric flood is not one;
        # it is the Z-Score engine's responsibility. Without these rows the
        # region is unpopulated, so a 1-port 1500-pps flood falls nearest the
        # high-magnitude Scan samples and is misreported as a scan.
        seed = [
            [1, 5, "Normal"],
            [5, 25, "Normal"],
            [10, 50, "Normal"],
            [15, 80, "Normal"],
            [1, 800, "Normal"],
            [2, 2000, "Normal"],
            [3, 6000, "Normal"],
            [1, 15000, "Normal"],
            [30, 40, "Scan"],
            [50, 60, "Scan"],
            [100, 200, "Scan"],
            [500, 1000, "Scan"],
        ]
        self.training_data.extend(seed)
        self._ranges = None
        print("[*] KNN Initialized with %d training samples." % len(self.training_data))

    def euclidean_distance(self, p1, p2):
        return math.sqrt(sum((a - b) ** 2 for a, b in zip(p1, p2)))

    # ---- feature engineering and scaling --------------------------------
    @staticmethod
    def _features(unique_ports, packet_count):
        """Build the full feature vector, deriving the ports/packets ratio."""
        ports = float(unique_ports)
        pkts = float(packet_count)
        return [ports, pkts, ports / pkts if pkts > 0 else 0.0]

    def feature_ranges(self):
        """Per-feature (min, max) taken from the training set, cached.

        Euclidean distance is not scale invariant. `packet_count` spans roughly
        5-15000 while `unique_ports` spans 1-500, so an unscaled metric is
        dominated almost entirely by the packet count, and the port dimension -
        the feature that actually defines a scan - contributes almost nothing.
        Min-max normalising every axis onto [0, 1] restores equal weight.
        """
        if self._ranges is None:
            if not self.training_data:
                self._ranges = [(0.0, 1.0)] * 3
            else:
                vectors = [self._features(r[0], r[1])
                           for r in self.training_data]
                self._ranges = [(min(v[i] for v in vectors),
                                 max(v[i] for v in vectors))
                                for i in range(3)]
        return self._ranges

    def _scale(self, vector):
        scaled = []
        for value, (low, high) in zip(vector, self.feature_ranges()):
            span = high - low
            scaled.append((float(value) - low) / span if span > 0 else 0.0)
        return scaled

    @classmethod
    def _is_plausible_scan(cls, ports, pkts):
        ratio = ports / pkts if pkts > 0 else 0.0
        return bool(
            pkts > 0
            and cls.MIN_SCAN_PORTS <= ports <= pkts
            and ratio >= cls.MIN_SCAN_RATIO
        )

    @classmethod
    def _sanitise_training_data(cls, samples):
        """Validate binary KNN rows and repair impossible Scan labels."""
        cleaned = []
        corrected = 0
        for row in samples:
            if not isinstance(row, (list, tuple)) or len(row) < 3:
                corrected += 1
                continue
            try:
                ports = float(row[0])
                pkts = float(row[1])
            except (TypeError, ValueError):
                corrected += 1
                continue
            if (not math.isfinite(ports) or not math.isfinite(pkts)
                    or ports < 0 or pkts <= 0 or ports > pkts):
                corrected += 1
                continue

            label = "Scan" if str(row[2]).strip().lower() == "scan" else "Normal"
            if label == "Scan" and not cls._is_plausible_scan(ports, pkts):
                label = "Normal"
                corrected += 1
            cleaned.append([ports, pkts, label])
        return cleaned, corrected

    def classify(self, unique_ports, packet_count):
        features = self._features(unique_ports, packet_count)
        ports, pkts, ratio = features

        # Semantic guardrails sit in front of the learned classifier. KNN can
        # only compare a point with its training data; it does not understand
        # that zero ports cannot be a port scan. These invariants also protect
        # runtime detection from a mislabeled or incompatible imported brain.
        if not self._is_plausible_scan(ports, pkts):
            return "Normal", []

        point = self._scale(features)
        dists = []
        for ports, pkts, label in self.training_data:
            d = self.euclidean_distance(point,
                                        self._scale(self._features(ports, pkts)))
            dists.append((d, label))

        dists.sort(key=lambda x: x[0])
        nearest = dists[:self.k]

        # Distance-weighted vote, each neighbour contributing 1/d.
        #
        # Plain majority voting treats all k neighbours as equally
        # authoritative, so an observation identical to a known Scan sample can
        # still be outvoted by two samples that are further away. Weighting by
        # inverse distance makes a closer neighbour count for more, which is
        # what resolves the boundary between busy-but-legitimate traffic and a
        # slow scan. Epsilon keeps an exact match finite rather than dividing
        # by zero.
        scan_weight = normal_weight = 0.0
        for d, label in nearest:
            weight = 1.0 / (d + 1e-9)
            if label == "Scan":
                scan_weight += weight
            else:
                normal_weight += weight

        return ("Scan" if scan_weight > normal_weight else "Normal"), nearest

    # ---- uniform engine interface (NFR-5) ------------------------------
    def analyse(self, unique_ports, packet_count):
        verdict, nearest = self.classify(unique_ports, packet_count)
        # confidence = share of the k neighbours voting for the winning label
        votes = sum(1 for _, lbl in nearest if lbl == verdict)
        confidence = votes / float(len(nearest)) if nearest else 0.0
        return Verdict(
            verdict,
            confidence=confidence,
            detail={"unique_ports": unique_ports, "packet_count": packet_count,
                    "neighbours": [(round(d, 3), l) for d, l in nearest]},
            is_threat=(verdict == "Scan"),
        )

    def train(self, samples, max_samples=5000):
        """Store labelled (ports, packets, label) rows; KNN is a lazy learner.

        Above max_samples the set is down-sampled per class so one dominant
        label cannot crowd out the minority class in the neighbour vote.
        """
        rows, corrected = self._sanitise_training_data(samples)
        if len(rows) > max_samples:
            buckets = {}
            for row in rows:
                buckets.setdefault(row[2], []).append(row)
            per = max(1, max_samples // max(1, len(buckets)))
            kept = []
            for items in buckets.values():
                step = max(1, len(items) // per)
                kept.extend(items[::step][:per])
            rows = kept
        self.training_data = rows
        self._ranges = None          # recompute scaling for the new data
        counts = Counter(r[2] for r in rows)
        print("[KNN] %d samples %s%s"
              % (len(rows), dict(counts),
                 " (%d invalid labels/rows corrected)" % corrected
                 if corrected else ""))
        return {"samples": len(rows), "classes": dict(counts),
                "corrected": corrected}

    def export_brain(self):
        return {"k": self.k, "training_data": self.training_data}

    def import_brain(self, data):
        if "training_data" in data:
            cleaned, corrected = self._sanitise_training_data(
                data["training_data"])
            if not cleaned:
                print("[!] KNN brain contained no valid signatures; "
                      "keeping safe built-in seed data.")
                return False
            self.training_data = cleaned
            self._ranges = None      # rescale against the imported data
            print("[*] Federate Learning: KNN loaded %d external signatures"
                  "%s."
                  % (len(self.training_data),
                     " (%d corrected)" % corrected if corrected else ""))
            return True
        return False


if __name__ == "__main__":
    e = KNNMonitor(k=3)
    print("feature ranges (min,max): %s" % e.feature_ranges())
    cases = [
        (1, 12, "idle host"),
        (12, 75, "normal browsing"),
        (25, 150, "busy browsing (CDNs, ads)"),
        (45, 50, "slow scan"),
        (400, 800, "aggressive scan"),
        (1, 1500, "SYN flood - must NOT be a scan"),
        (2, 8000, "heavy flood - must NOT be a scan"),
    ]
    for ports, pkts, note in cases:
        verdict, _ = e.classify(ports, pkts)
        ratio = ports / float(pkts)
        print("ports=%-4d pkts=%-6d ratio=%.3f -> %-7s (%s)"
              % (ports, pkts, ratio, verdict, note))

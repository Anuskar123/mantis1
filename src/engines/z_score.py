import collections
import math

try:
    from engines.base import DetectionEngine, Verdict
except ImportError:  # allow `python engines/z_score.py` direct execution
    from base import DetectionEngine, Verdict


class MinimalistStats(DetectionEngine):
    """Volumetric flood detection from packets-per-second statistics.

    Two estimators run side by side:

    * a bounded rolling window (deque, maxlen=window_size) giving the *recent*
      mean and standard deviation, so the baseline adapts when legitimate
      traffic shifts and old behaviour is forgotten;
    * Welford's online algorithm (Welford, 1962) maintaining the mean and
      variance of the entire session in constant space, updated incrementally
      per observation with no stored history.

    Welford is used because the naive "sum of squares minus square of sum"
    formulation loses catastrophic precision once the running totals grow
    large, which is exactly the regime a flood produces. Welford instead
    accumulates the second central moment directly:

        n     <- n + 1
        delta <- x - mean
        mean  <- mean + delta / n
        M2    <- M2 + delta * (x - mean_new)
        var   <- M2 / n                       (population variance)

    The rolling window remains the operational detector (it must forget), while
    the Welford figures provide the stable session-wide statistics quoted in
    the evaluation chapter.
    """

    name = "z_score"
    features = ("packets_per_second",)

    # A single outlier inside a population of n samples can never score higher
    # than (n-1)/sqrt(n). With the default window of 30 that ceiling is 5.29,
    # but it collapses toward the threshold as an attack fills the window.
    MIN_WARMUP = 5

    def __init__(self, window_size=30, threshold=3.0, guard_baseline=True,
                 min_pps=500, required_consecutive=1):
        self.window_size = window_size
        self.threshold = threshold
        # A high Z-score only means "unusual for this host". Requiring a
        # meaningful absolute packet rate prevents small changes such as
        # 10 -> 50 PPS from being mislabeled as a volumetric DDoS attack.
        self.min_pps = max(0, float(min_pps))
        self.required_consecutive = max(1, int(required_consecutive))
        self.anomaly_streak = 0
        # guard_baseline=False reproduces the naive estimator for comparison
        self.guard_baseline = guard_baseline
        self.history = collections.deque(maxlen=window_size)

        # Welford accumulators (whole session, constant memory)
        self.count = 0
        self.w_mean = 0.0
        self.w_m2 = 0.0
        self.peak = 0
        self.suppressed = 0     # observations kept out of the baseline

    @property
    def max_detectable_z(self):
        """Theoretical ceiling on the z-score of one outlier: (n-1)/sqrt(n)."""
        n = len(self.history)
        if n < 2:
            return 0.0
        return (n - 1) / math.sqrt(n)

    # ---- online update -------------------------------------------------
    def update(self, packet_count):
        self.history.append(packet_count)

        # Welford incremental update
        self.count += 1
        delta = packet_count - self.w_mean
        self.w_mean += delta / self.count
        self.w_m2 += delta * (packet_count - self.w_mean)

        if packet_count > self.peak:
            self.peak = packet_count

    def calculate_baseline(self):
        """Rolling-window mean and population standard deviation."""
        if len(self.history) < 2:
            return 0.0, 0.0

        data = list(self.history)
        n = len(data)
        mean = sum(data) / n

        # population variance (we want the actual spread, not a sample estimate)
        var = sum((x - mean) ** 2 for x in data) / n
        return mean, math.sqrt(var)

    def welford_baseline(self):
        """Session-wide mean and population standard deviation, O(1) memory."""
        if self.count < 2:
            return self.w_mean, 0.0
        return self.w_mean, math.sqrt(self.w_m2 / self.count)

    def z_of(self, packet_count):
        """Z = (x - mu) / sigma against the rolling baseline."""
        mean, std = self.calculate_baseline()
        if std <= 0:
            return 0.0
        return (packet_count - mean) / std

    # ---- uniform engine interface (NFR-5) ------------------------------
    def analyse(self, packets_per_second, update=True):
        """Score an observation against the baseline, then update it.

        Two corrections to the naive estimator are applied here, and together
        they are what lifts flood recall:

        1. Predict-then-update. The observation is scored against the baseline
           *as it stood before the observation arrived*. Folding the sample in
           first inflates the mean and the standard deviation with the very
           spike being measured, capping any single outlier at (n-1)/sqrt(n)
           and hiding genuine floods.

        2. Baseline poisoning guard. An observation judged anomalous is not
           admitted into the baseline. Without this, a sustained flood is
           absorbed within `window_size` seconds: the mean climbs to attack
           volume, the z-score decays to zero and the alert silently stops
           while the attack is still running. This failure mode is the direct
           cause of the low flood recall reported for the naive estimator.
        """
        mean, std = self.calculate_baseline()

        warm = len(self.history) >= self.MIN_WARMUP
        z = (packets_per_second - mean) / std if std > 0 else 0.0
        statistical_anomaly = bool(
            warm and std > 0 and z > self.threshold)
        volume_candidate = bool(
            statistical_anomaly and packets_per_second >= self.min_pps)

        if volume_candidate:
            self.anomaly_streak += 1
        else:
            self.anomaly_streak = 0

        is_threat = bool(
            volume_candidate
            and self.anomaly_streak >= self.required_consecutive)
        new_threat = bool(
            volume_candidate
            and self.anomaly_streak == self.required_consecutive)

        # Keep genuine high-volume candidates out of the baseline while their
        # persistence is being confirmed. Low-volume statistical changes are
        # normal operating drift and must be allowed to update the baseline.
        if update and not (volume_candidate and self.guard_baseline):
            self.update(packets_per_second)
        elif volume_candidate:
            self.suppressed += 1

        # map z onto 0..1 so the risk scorer has a confidence signal
        confidence = (
            min(1.0, abs(z) / (self.threshold * 2))
            if volume_candidate and std > 0 else 0.0
        )
        return Verdict(
            "DDoS" if is_threat else "Normal",
            confidence=confidence,
            detail={"z_score": round(z, 4), "mean": round(mean, 2),
                    "std_dev": round(std, 4), "pps": packets_per_second,
                    "warm": warm, "baseline_samples": len(self.history),
                    "statistical_anomaly": statistical_anomaly,
                    "volume_candidate": volume_candidate,
                    "min_pps": self.min_pps,
                    "anomaly_streak": self.anomaly_streak,
                    "required_consecutive": self.required_consecutive,
                    "new_threat": new_threat},
            is_threat=is_threat,
        )

    def train(self, samples):
        """Warm the baseline from an iterable of packets-per-second values."""
        seen = 0
        for value in samples:
            if isinstance(value, (list, tuple)):
                value = value[0]        # tolerate (pps, label) rows
            self.update(float(value))
            seen += 1
        mean, std = self.welford_baseline()
        print("[ZS ] %d observations mean=%.2f std=%.2f peak=%d"
              % (seen, mean, std, self.peak))
        return {"samples": seen, "mean": mean, "std_dev": std, "peak": self.peak}

    def export_brain(self):
        return {
            "window_size": self.window_size,
            "threshold": self.threshold,
            "guard_baseline": self.guard_baseline,
            "min_pps": self.min_pps,
            "required_consecutive": self.required_consecutive,
            "count": self.count,
            "mean": self.w_mean,
            "m2": self.w_m2,
            "peak": self.peak,
            "history": list(self.history),
        }

    def import_brain(self, data):
        if not isinstance(data, dict):
            return False
        # Restore learned observations, but keep the current runtime policy
        # authoritative. Otherwise an old brain file silently overrides newer
        # CLI/config values such as threshold, window, and minimum PPS.
        self.count = int(data.get("count", 0))
        self.w_mean = float(data.get("mean", 0.0))
        self.w_m2 = float(data.get("m2", 0.0))
        self.peak = int(data.get("peak", 0))
        self.history = collections.deque(data.get("history", []),
                                         maxlen=self.window_size)
        self.anomaly_streak = 0
        print("[*] Federated Learning: Z-Score restored baseline "
              "(mean=%.2f over %d observations)." % (self.w_mean, self.count))
        return True

    def reset(self):
        self.history.clear()
        self.count = 0
        self.w_mean = 0.0
        self.w_m2 = 0.0
        self.peak = 0
        self.suppressed = 0
        self.anomaly_streak = 0
        return True


if __name__ == "__main__":
    baseline_traffic = [10, 12, 11, 10, 13, 9, 11, 12, 10, 11]

    s = MinimalistStats(window_size=10)
    for pps in baseline_traffic:
        s.update(pps)
    wm, wsd = s.welford_baseline()

    # Welford must agree with the textbook two-pass formula
    mean = sum(baseline_traffic) / len(baseline_traffic)
    ref = math.sqrt(sum((x - mean) ** 2 for x in baseline_traffic)
                    / len(baseline_traffic))
    print("welford  mean=%.4f std=%.4f" % (wm, wsd))
    print("two-pass mean=%.4f std=%.4f  (delta=%.2e)"
          % (mean, ref, abs(ref - wsd)))
    print("max detectable z for a single outlier (n=%d): %.3f"
          % (len(s.history), s.max_detectable_z))

    # A sustained 60-second flood: how many seconds does each variant catch?
    flood = [8000] * 60
    print("\nsustained flood of %d seconds at 8000 pps" % len(flood))
    for guarded in (False, True):
        eng = MinimalistStats(window_size=10, threshold=3.0,
                              guard_baseline=guarded)
        eng.train(baseline_traffic)
        caught = sum(1 for pps in flood if eng.analyse(pps).is_threat)
        print("  guard_baseline=%-5s -> detected %2d/%d seconds (recall %.2f)"
              % (guarded, caught, len(flood), caught / len(flood)))

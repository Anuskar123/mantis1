import math

try:
    from engines.base import DetectionEngine, Verdict
except ImportError:  # allow `python engines/kmeans.py` direct execution
    from base import DetectionEngine, Verdict

# Cluster 0 is the idle/normal profile, 1 the high-volume profile and 2 the
# wide-port-spread profile, matching the seeded centroids below.
ANOMALY_CLUSTER = 2
CLUSTER_LABELS = {0: "Idle", 1: "High Volume", 2: "Port Spread"}


class KMeansMonitor(DetectionEngine):
    # online (mini-batch) k-means - centroids drift toward live traffic
    # so the model adapts as the network changes

    name = "kmeans"
    features = ("packets_per_second", "unique_ports")

    def __init__(self, k=3, learning_rate=0.1, radius_multiplier=3.0,
                 min_samples=8):
        self.k = k
        self.alpha = learning_rate

        # default clusters: idle / ddos / scanner
        # picked manually so we don't need an offline training pass to start
        self.centroids = [
            [10.0, 2.0],
            [200.0, 5.0],
            [20.0, 50.0],
        ]

        # Novelty detection over the *reconstruction error* - the distance from
        # each observation to its nearest centroid.
        #
        # Testing cluster identity (the previous `cluster == 2` rule) cannot
        # detect novelty: every point is assigned to some cluster, so traffic
        # unlike anything seen before is silently absorbed into whichever
        # centroid happens to be least distant. Testing distance instead is
        # what turns clustering into an anomaly detector.
        #
        # The statistics are pooled across all clusters rather than kept
        # per-cluster. Attack traffic is by definition rare, so an
        # attack-region cluster would never accumulate enough observations to
        # finish warming up, and a per-cluster threshold would stay disabled
        # exactly when it was needed. Pooling means the model calibrates on the
        # abundant normal traffic and is immediately usable.
        self.radius_multiplier = radius_multiplier
        self.min_samples = min_samples
        self.dist_count = 0
        self.dist_mean = 0.0
        self.dist_m2 = 0.0
        self.cluster_counts = [0] * k

    def euclidean_distance(self, a, b):
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    def classify(self, pps, unique_ports):
        point = [float(pps), float(unique_ports)]

        best_dist = float("inf")
        best = 0
        for i, c in enumerate(self.centroids):
            d = self.euclidean_distance(point, c)
            if d < best_dist:
                best_dist = d
                best = i

        self._update_centroid(best, point)
        return best

    def _update_centroid(self, idx, point):
        # c_new = c_old + alpha * (point - c_old)
        old = self.centroids[idx]
        self.centroids[idx] = [o + self.alpha * (p - o) for o, p in zip(old, point)]

    def distances(self, pps, unique_ports):
        point = [float(pps), float(unique_ports)]
        return [self.euclidean_distance(point, c) for c in self.centroids]

    # ---- uniform engine interface (NFR-5) ------------------------------
    def analyse(self, pps, unique_ports, update=True):
        """Assign the observation to a cluster and test it for novelty.

        Anomaly criterion: distance to the assigned centroid exceeds
        `radius_multiplier` times that cluster's running mean radius, once the
        cluster has seen at least `min_samples` observations. Before the warm-up
        threshold the radius estimate is meaningless, so nothing is flagged and
        the engine cannot produce start-up false positives.

        Confidence is how far beyond the radius the point sits, capped at 1.0.
        """
        dists = self.distances(pps, unique_ports)
        best = min(range(len(dists)), key=lambda i: dists[i])
        nearest = dists[best]

        mean, std = self.distance_baseline()
        warm = self.dist_count >= self.min_samples
        # mu + k*sigma, falling back to a multiple of the mean when the
        # observed distances have not varied at all (std == 0)
        limit = (mean + self.radius_multiplier * std if std > 0
                 else mean * self.radius_multiplier)

        is_threat = bool(warm and limit > 0 and nearest > limit)
        # 1 - limit/distance rises monotonically toward 1 without ever
        # reaching it, so "far outside the threshold" and "extremely far
        # outside" remain distinguishable instead of both clamping to 1.0
        confidence = (1.0 - (limit / nearest)) if is_threat else 0.0

        if update and not is_threat:
            # Only non-anomalous points are folded into the model, so a
            # sustained attack cannot drag a centroid onto itself and then
            # declare the traffic normal (the same poisoning guard the
            # Z-Score engine applies to its baseline).
            self.cluster_counts[best] += 1
            self.dist_count += 1
            delta = nearest - self.dist_mean
            self.dist_mean += delta / self.dist_count
            self.dist_m2 += delta * (nearest - self.dist_mean)
            self._update_centroid(best, [float(pps), float(unique_ports)])

        return Verdict(
            CLUSTER_LABELS.get(best, "Cluster %d" % best),
            confidence=confidence,
            detail={"cluster": best, "distance": round(nearest, 3),
                    "mean_distance": round(mean, 3),
                    "threshold": round(limit, 3),
                    "samples": self.dist_count,
                    "centroid": [round(v, 2) for v in self.centroids[best]]},
            is_threat=is_threat,
        )

    def distance_baseline(self):
        """Mean and population std-dev of nearest-centroid distance (Welford)."""
        if self.dist_count < 2:
            return self.dist_mean, 0.0
        return self.dist_mean, math.sqrt(self.dist_m2 / self.dist_count)

    def train(self, points, iters=25, tolerance=1e-3):
        """Batch Lloyd's algorithm to place the initial centroids.

        Online updates then let the centroids drift with live traffic, but a
        batch pass first gives them a data-driven starting position instead of
        the hand-picked seeds.
        """
        pts = [[float(v) for v in p] for p in points]
        if len(pts) < self.k:
            raise ValueError("need at least %d points" % self.k)

        step = max(1, len(pts) // self.k)
        self.centroids = [list(pts[i * step]) for i in range(self.k)]

        for _ in range(iters):
            groups = [[] for _ in range(self.k)]
            for p in pts:
                idx = min(range(self.k),
                          key=lambda i: self.euclidean_distance(p, self.centroids[i]))
                groups[idx].append(p)
            moved = 0.0
            for i, group in enumerate(groups):
                if not group:
                    continue
                new = [sum(m[j] for m in group) / len(group)
                       for j in range(len(group[0]))]
                moved += self.euclidean_distance(self.centroids[i], new)
                self.centroids[i] = new
            if moved < tolerance:
                break

        inertia = sum(min(self.euclidean_distance(p, c) ** 2
                          for c in self.centroids) for p in pts)

        # Persist the normal-distance distribution with the centroids. This
        # lets a freshly imported brain classify novelty immediately instead
        # of relearning its warm-up baseline from live traffic.
        self.dist_count = 0
        self.dist_mean = 0.0
        self.dist_m2 = 0.0
        self.cluster_counts = [0] * self.k
        for p in pts:
            idx = min(range(self.k),
                      key=lambda i: self.euclidean_distance(p,
                                                            self.centroids[i]))
            distance = self.euclidean_distance(p, self.centroids[idx])
            self.cluster_counts[idx] += 1
            self.dist_count += 1
            delta = distance - self.dist_mean
            self.dist_mean += delta / self.dist_count
            self.dist_m2 += delta * (distance - self.dist_mean)

        print("[KM ] %d centroids on %d points: %s"
              % (self.k, len(pts), [[round(v, 2) for v in c]
                                    for c in self.centroids]))
        mean, std = self.distance_baseline()
        return {"points": len(pts), "centroids": self.centroids,
                "inertia": round(inertia, 3),
                "distance_mean": round(mean, 6),
                "distance_std": round(std, 6)}

    def export_brain(self):
        return {"k": self.k, "alpha": self.alpha, "centroids": self.centroids,
                "dist_count": self.dist_count, "dist_mean": self.dist_mean,
                "dist_m2": self.dist_m2,
                "cluster_counts": self.cluster_counts}

    def import_brain(self, data):
        if "centroids" in data:
            self.centroids = data["centroids"]
            self.k = len(self.centroids)
            # tolerate brains saved before distance stats were tracked
            self.dist_count = int(data.get("dist_count", 0))
            self.dist_mean = float(data.get("dist_mean", 0.0))
            self.dist_m2 = float(data.get("dist_m2", 0.0))
            self.cluster_counts = list(data.get("cluster_counts",
                                                [0] * self.k))
            while len(self.cluster_counts) < self.k:
                self.cluster_counts.append(0)
            print("[*] Federate Learning: K-Means loaded %d external centroids."
                  % len(self.centroids))
            return True
        return False


if __name__ == "__main__":
    km = KMeansMonitor(k=3, learning_rate=0.1)

    # learn what "normal" looks like for this host
    print("warm-up on 20 seconds of idle traffic")
    for i in range(20):
        km.analyse(10 + (i % 3), 2)
    m, sd = km.distance_baseline()
    print("  nearest-centroid distance: mean=%.3f std=%.3f over %d samples"
          % (m, sd, km.dist_count))

    print("\nnow score traffic the host has never seen:")
    for pps, ports, note in [
        (11, 2, "more idle traffic"),
        (60, 45, "moderate scan-like spread"),
        (9000, 1, "massive flood"),
        (300, 400, "wide port sweep"),
    ]:
        v = km.analyse(pps, ports)
        print("  pps=%-5d ports=%-4d -> %-12s anomaly=%-5s dist=%.1f thr=%.1f"
              % (pps, ports, v.label, v.is_threat,
                 v.detail["distance"], v.detail["threshold"]))

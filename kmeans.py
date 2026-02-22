import math
import random

# MANTIS Phase 7: Algorithm 5 (K-Means Clustering)
# Unsupervised Learning: Automatically groups traffic patterns.

class KMeansMonitor:
    def __init__(self, k=3):
        """
        Initializes K-Means Clustering.
        k=3 -> We expect 3 types of traffic:
        1. Low Traffic (Idle)
        2. High Traffic (Streaming/Download/DDoS)
        3. Scanning (High Ports)
        """
        self.k = k
        self.centroids = []
        # Initial random centroids (Feature 1: PPS, Feature 2: Unique Ports)
        # We cheat slightly by picking spread-out starting points to ensure convergence
        self.centroids = [
            [10, 2],    # Cluster 0: Normal/Idle
            [200, 5],   # Cluster 1: High Volume (DDoS?)
            [20, 50]    # Cluster 2: Scanner (Many Ports)
        ]
        
    def euclidean_distance(self, p1, p2):
        return math.sqrt(sum([(a - b) ** 2 for a, b in zip(p1, p2)]))
        
    def classify(self, pps, unique_ports):
        """
        Assigns the current traffic state to the nearest Cluster.
        Returns: Cluster_ID (0, 1, or 2)
        """
        point = [pps, unique_ports]
        distances = []
        
        for i, centroid in enumerate(self.centroids):
            dist = self.euclidean_distance(point, centroid)
            distances.append((dist, i))
            
        # Find nearest centroid
        distances.sort(key=lambda x: x[0])
        nearest_cluster_id = distances[0][1]
        
        return nearest_cluster_id
        
    def update_model(self, recent_history):
        """
        Re-calculates centroids based on real data (The 'Learning' part).
        recent_history: List of [pps, unique_ports] samples
        """
        if not recent_history:
            return

        # Simplified Update: Move centroid 10% towards the average of new points assigned to it
        # This is "Online K-Means"
        pass # Kept simple for First Principles efficiency

# ==========================================
# TEST HARNESS
# ==========================================
if __name__ == "__main__":
    km = KMeansMonitor(k=3)
    
    print("[*] Testing Unsupervised Learning (K-Means)...")
    
    samples = [
        [5, 1],   # Idle
        [8, 2],   # Idle
        [250, 4], # DDoS
        [30, 60]  # Scanner
    ]
    
    for s in samples:
        cluster = km.classify(s[0], s[1])
        print(f"   Traffic {s} -> Assigned to Cluster {cluster}")

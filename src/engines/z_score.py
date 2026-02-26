import math
import collections

# MANTIS Phase 2: Statistical Engine
# Step 1: Baseline Traffic Analysis (First Principles Math)

class MinimalistStats:
    def __init__(self, window_size=30):
        """
        Initializes the Statistical Engine.
        window_size: How many seconds of history to keep for the baseline.
        """
        # We use a deque (double-ended queue) to store the last N samples.
        # When we add a new sample, the oldest one is automatically removed.
        self.history = collections.deque(maxlen=window_size)
    
    def update(self, packet_count):
        """
        Adds a new 'Packets Per Second' (PPS) sample to the history.
        """
        self.history.append(packet_count)
        
    def calculate_baseline(self):
        """
        Calculates the Mean (Average) and Standard Deviation (Volatility) 
        of the traffic history manually.
        """
        if len(self.history) < 2:
            return 0.0, 0.0
            
        # 1. Calculate Mean (mu)
        # Formula: Sum(X) / N
        data = list(self.history)
        n = len(data)
        mean = sum(data) / n
        
        # 2. Calculate Variance (sigma squared)
        # Formula: Sum((X - mu)^2) / N
        # This measures how spread out the data is.
        squared_diff_sum = 0
        for x in data:
            squared_diff_sum += (x - mean) ** 2
            
        variance = squared_diff_sum / n
        
        # 3. Calculate Standard Deviation (sigma)
        # Formula: Sqrt(Variance)
        std_dev = math.sqrt(variance)
        
        return mean, std_dev

# ==========================================
# TEST HARNESS (Run this file directly)
# ==========================================
if __name__ == "__main__":
    print("[*] Testing Statistical Engine (First Principles)...")
    
    stats = MinimalistStats(window_size=10)
    
    # Simulate normal traffic (random small numbers)
    normal_traffic = [10, 12, 11, 10, 13, 9, 11, 12, 10, 11]
    
    print("\n[Phase 1] Learning Baseline (Normal Traffic):")
    for pps in normal_traffic:
        stats.update(pps)
        mu, sigma = stats.calculate_baseline()
        print(f"   PPS: {pps} | Mean: {mu:.2f} | StdDev: {sigma:.2f}")
        
    print("\n[Phase 2] Analyzing Stability:")
    print(f"   Final Baseline -> Mean: {mu:.2f}, StdDev: {sigma:.2f}")
    print("   Interpretation: Normal traffic is around 11 packets/sec with very little variation.")

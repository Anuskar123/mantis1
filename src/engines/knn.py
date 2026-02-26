import math
import collections

# MANTIS Phase 3: Behavioral Engine (K-Nearest Neighbors)
# Step 1: Logic & Math Implementation

class KNNMonitor:
    def __init__(self, k=3):
        """
        Initializes the KNN Classifier.
        k: Number of neighbors to check (k=3 is standard for simple binary classification).
        """
        self.k = k
        self.training_data = [] # Stores [Feature_1, Feature_2, Label]
        
        # ---------------------------------------------------------
        # 1. Internal Training Data (The "Knowledge Base")
        # ---------------------------------------------------------
        # Feature 1: Number of Unique Ports hit in 1 second.
        # Feature 2: Packets Sent in 1 second.
        # Label: "Normal" or "Scan"
        
        # "Normal" behavior: User browse web (Port 80, 443), maybe check mail (993).
        # Modern websites load resources from many domains (CDNs, Ads), so 10-15 ports is normal.
        self.training_data.append([1, 5,   "Normal"]) # Idle
        self.training_data.append([5, 10,  "Normal"]) # Light Browsing
        self.training_data.append([10, 50, "Normal"]) # Heavy Site (CNN/Facebook)
        self.training_data.append([15, 80, "Normal"]) # Very Heavy Site
        
        # "Scan" behavior: Nmap hitting many random ports quickly.
        # Nmap -T3/T4 usually hits >1000 ports/sec, but let's catch slower scans too.
        self.training_data.append([30, 40,   "Scan"]) # Slow Scan
        self.training_data.append([50, 60,   "Scan"]) # Medium Scan
        self.training_data.append([100, 200, "Scan"]) # Fast Scan
        self.training_data.append([500, 1000,"Scan"]) # Aggressive Scan
        
        print(f"[*] KNN Initialized with {len(self.training_data)} training samples.")

    def euclidean_distance(self, point1, point2):
        """
        Calculates the distance between two points in 2D space.
        Formula: Sqrt( (x2 - x1)^2 + (y2 - y1)^2 )
        """
        x1, y1 = point1
        x2, y2 = point2
        return math.sqrt( (x2 - x1)**2 + (y2 - y1)**2 )

    def classify(self, unique_ports, packet_count):
        """
        The Core KNN Algorithm.
        1. Calculate distance from new point to ALL training points.
        2. Sort by distance (find closest).
        3. Vote (Normal vs Scan).
        """
        unknown_point = [unique_ports, packet_count]
        distances = []
        
        # 1. Measure Distance to every known case
        for item in self.training_data:
            known_point = item[:2] # Features
            label = item[2]        # Label
            dist = self.euclidean_distance(unknown_point, known_point)
            distances.append([dist, label])
            
        # 2. Sort by distance (Smallest = Closest)
        distances.sort(key=lambda x: x[0])
        
        # 3. Take closest K neighbors
        neighbors = distances[:self.k]
        
        # 4. Count Votes
        scan_votes = 0
        normal_votes = 0
        
        for n in neighbors:
            vote = n[1]
            if vote == "Scan":
                scan_votes += 1
            else:
                normal_votes += 1
                
        # 5. Final Verdict
        if scan_votes > normal_votes:
            return "Scan", neighbors # Return verdict and evidence
        else:
            return "Normal", neighbors

# ==========================================
# TEST HARNESS (Run this file directly)
# ==========================================
if __name__ == "__main__":
    print("[*] Testing Behavioral Engine (KNN)...")
    
    knn = KNNMonitor(k=3)
    
    print("\n[Test Case 1] User browsing Google (Port 443)")
    # Features: Hit 1 unique port, sent 12 packets
    verdict, evidence = knn.classify(1, 12)
    print(f"   Input: 1 Port, 12 Packets -> Verdict: {verdict}")
    
    print("\n[Test Case 2] Nmap Scan (nmap -sS -p 1-100 target)")
    # Features: Hit 45 unique ports, sent 50 packets
    verdict, evidence = knn.classify(45, 50)
    print(f"   Input: 45 Ports, 50 Packets -> Verdict: {verdict}")
    
    print("\n[Test Case 3] Aggressive Scan")
    verdict, evidence = knn.classify(12, 18)
    print(f"   Input: 12 Ports, 18 Packets -> Verdict: {verdict}")

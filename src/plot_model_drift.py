#!/usr/bin/env python3
import json
import glob
import os
import sys

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("[!] Error: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)

# A script to visualize "Model Drift" in the MANTIS K-Means algorithm over time.
# Perfect for generating graphs for the dissertation!

def plot_drift(data_dir="data"):
    # 1. Grab all the brain JSON files, sorted by time
    brain_files = sorted(glob.glob(os.path.join(data_dir, "*mantis_brain_*.json")))
    
    if not brain_files:
        print(f"[!] No brain files found in '{data_dir}/'")
        return

    print(f"[*] Found {len(brain_files)} historical brain states. Processing...")

    # We want to track the X and Y coordinates of each of the 3 Clusters over time.
    # Feature X: Packets Per Second (PPS)
    # Feature Y: Unique Ports
    history_c0_x, history_c0_y = [], []  # Cluster 0 (Idle)
    history_c1_x, history_c1_y = [], []  # Cluster 1 (DDoS)
    history_c2_x, history_c2_y = [], []  # Cluster 2 (Scan)

    # 2. Extract Data
    for fname in brain_files:
        try:
            with open(fname, 'r') as f:
                data = json.load(f)
                
            centroids = data.get("kmeans", {}).get("centroids", [])
            if len(centroids) == 3:
                history_c0_x.append(centroids[0][0])
                history_c0_y.append(centroids[0][1])
                
                history_c1_x.append(centroids[1][0])
                history_c1_y.append(centroids[1][1])
                
                history_c2_x.append(centroids[2][0])
                history_c2_y.append(centroids[2][1])
        except Exception as e:
            print(f"Error reading {fname}: {e}")

    # 3. Plotting
    plt.figure(figsize=(10, 6))
    
    # Plot the paths (arrows/lines showing movement)
    plt.plot(history_c0_x, history_c0_y, 'g-', alpha=0.5, label='Cluster 0 (Idle Profile) Path')
    plt.plot(history_c1_x, history_c1_y, 'r-', alpha=0.5, label='Cluster 1 (DDoS Profile) Path')
    plt.plot(history_c2_x, history_c2_y, 'b-', alpha=0.5, label='Cluster 2 (Scan Profile) Path')
    
    # Plot the exact dots where the centroids sat in each file
    plt.scatter(history_c0_x, history_c0_y, c='green', marker='o', s=50)
    plt.scatter(history_c1_x, history_c1_y, c='red', marker='x', s=50)
    plt.scatter(history_c2_x, history_c2_y, c='blue', marker='s', s=50)

    # Highlight the START (S) and FINISH (F) positions
    if len(brain_files) > 1:
        plt.text(history_c0_x[0], history_c0_y[0], ' S', color='green', fontsize=12, weight='bold')
        plt.text(history_c0_x[-1], history_c0_y[-1], ' F', color='green', fontsize=12, weight='bold')
        
        plt.text(history_c1_x[0], history_c1_y[0], ' S', color='red', fontsize=12, weight='bold')
        plt.text(history_c1_x[-1], history_c1_y[-1], ' F', color='red', fontsize=12, weight='bold')
        
        plt.text(history_c2_x[0], history_c2_y[0], ' S', color='blue', fontsize=12, weight='bold')
        plt.text(history_c2_x[-1], history_c2_y[-1], ' F', color='blue', fontsize=12, weight='bold')

    plt.title("MANTIS Unsupervised Machine Learning: K-Means Centroid Drift Over Time", fontsize=14)
    plt.xlabel("Feature 1: Local Packets Per Second (PPS)", fontsize=12)
    plt.ylabel("Feature 2: Unique Destination Ports", fontsize=12)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the graph as a picture
    output_filename = os.path.join(data_dir, "mantis_model_drift_graph.png")
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"\n[+] Success! Graph saved to: {output_filename}")
    
    # Show it on the screen
    plt.show()

if __name__ == "__main__":
    print("""
    ========================================================
       MANTIS: K-Means Model Drift Visualizer (for Thesis)
    ========================================================
    """)
    plot_drift()

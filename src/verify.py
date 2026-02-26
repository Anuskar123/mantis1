import engines.z_score as z_score
import engines.knn as knn
import engines.naive_bayes as naive_bayes
import engines.bloom as bloom
import time
import math

# MANTIS Verification Script
# RUN THIS ON WINDOWS/LINUX TO TEST LOGIC (Without needing Raw Sockets)

def test_engines():
    print("================================================================")
    print("   MANTIS ENGINE VERIFICATION (Windows Compatible Mode)")
    print("================================================================")
    
    # ---------------------------------------------------------
    # TEST 1: Statistical Engine (Z-Score)
    # ---------------------------------------------------------
    print("\n[TEST 1] Testing Z-Score Engine (DDoS Detection)...")
    stats = z_score.MinimalistStats(window_size=10)
    
    # Feed VARIABLE normal traffic (to generate a Standard Deviation > 0)
    # If standard deviation is 0, Z-Score is 0. We need variance!
    traffic = [10, 12, 11, 10, 13, 9, 11, 12, 10, 11]
    for pps in traffic:
        stats.update(pps)
    
    mean, std = stats.calculate_baseline()
    print(f"   Baseline Established -> Mean: {mean:.2f}, StdDev: {std:.2f}")
    
    # Feed Attack Traffic (100 packets/sec)
    packet_count = 100
    z = (packet_count - mean) / std if std > 0 else 0
    print(f"   Attack Traffic (100 pps) -> Z-Score: {z:.2f}")
    
    if z > 3:
        print("   [PASS] Z-Score correctly flagged anomaly.")
    else:
        print("   [FAIL] Z-Score failed to flag anomaly. (Check standard deviation)")

    # ---------------------------------------------------------
    # TEST 2: Behavior Engine (KNN)
    # ---------------------------------------------------------
    print("\n[TEST 2] Testing KNN Engine (Port Scan Detection)...")
    try:
        knn_engine = knn.KNNMonitor()
        
        # Simulate Port Scan: 100 packets, 100 unique ports
        verdict, _ = knn_engine.classify(unique_ports=100, packet_count=100)
        print(f"   Input: 100 Unique Ports / 100 Packets -> Verdict: {verdict}")
        
        if verdict == "Scan":
            print("   [PASS] KNN correctly identified Port Scan.")
        else:
            print("   [FAIL] KNN failed to identify Port Scan.")
    except Exception as e:
        print(f"   [ERROR] KNN module failed: {e}")

    # ---------------------------------------------------------
    # TEST 3: Payload Engine (Naive Bayes)
    # ---------------------------------------------------------
    print("\n[TEST 3] Testing Naive Bayes Engine (SQL Injection)...")
    try:
        if not hasattr(naive_bayes, 'PayloadMonitor'):
            print(f"   [DEBUG] naive_bayes module content: {dir(naive_bayes)}")
            print("   [ERROR] 'PayloadMonitor' class not found in naive_bayes.py!")
            print("           Please check if you copied naive_bayes.py correctly.")
        else:
            nb = naive_bayes.PayloadMonitor()
            
            # Simulate SQL Injection Payload
            payload = b"GET /?q=UNION SELECT password FROM users"
            verdict, score, words = nb.classify(payload)
            print(f"   Input: '{payload.decode()}'")
            print(f"   Verdict: {verdict} | Score: {score} | Words: {words}")
            
            if verdict == "Malicious":
                print("   [PASS] Naive Bayes correctly identified SQL Injection.")
            else:
                print("   [FAIL] Naive Bayes failed to identify SQL Injection.")
    except Exception as e:
        print(f"   [ERROR] Naive Bayes module failed: {e}")

    # ---------------------------------------------------------
    # TEST 4: Reputation Engine (Bloom Filter)
    # ---------------------------------------------------------
    print("\n[TEST 4] Testing Bloom Filter (Blacklist)...")
    try:
        bf = bloom.BloomFilter()
        bad_ip = "192.168.1.66"
        bf.add(bad_ip)
        
        exists = bf.check(bad_ip)
        print(f"   Added '{bad_ip}' to Blacklist.")
        print(f"   Checking '{bad_ip}' -> {exists}")
        
        if exists:
            print("   [PASS] Bloom Filter correctly blocked IP.")
        else:
            print("   [FAIL] Bloom Filter failed to block IP.")
    except Exception as e:
        print(f"   [ERROR] Bloom Filter module failed: {e}")

    print("\n================================================================")
    print("   VERIFICATION COMPLETE")
    print("================================================================")

if __name__ == "__main__":
    test_engines()

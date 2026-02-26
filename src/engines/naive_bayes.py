import re

# MANTIS Phase 4: Payload Engine (Naive Bayes / Probabilistic Analysis)
# Step 1: Logic & Keyword Probability Implementation

class PayloadMonitor:
    def __init__(self):
        """
        Initializes the Probabilistic Payload Analyzer.
        We use a simplified Bayesian approach where specific keywords increase
        the probability of a payload being malicious.
        """
        # ---------------------------------------------------------
        # 1. Knowledge Base (The "Bad Words")
        # ---------------------------------------------------------
        # We assign a "Weight" (Probability) to each suspicious keyword.
        # High score (1.0) = Almost certainly an attack.
        # Low score (0.2)  = Could be benign, but suspicious if many appear.
        self.sus_keywords = {
            "UNION": 1.0,      # SQL Injection
            "SELECT": 0.8,     # SQL extraction
            "SLEEP": 0.9,      # Time-based Blind SQLi
            "DROP": 1.0,       # Dropping tables
            "INSERT": 0.6,     # Data modification
            "UPDATE": 0.6,     # Data modification
            "OR 1=1": 1.0,     # Classic Logic Bypass
            "SCRIPT": 0.9,     # XSS (Cross-Site Scripting)
            "ALERT(": 0.8,     # XSS
            "/ETC/PASSWD": 1.0,# Path Traversal (LFI)
            "ROOT": 0.4,       # Sensitive username
            "ADMIN": 0.4       # Sensitive username
        }
        
    def classify(self, payload_bytes):
        """
        Analyzes the payload (bytes) to calculate an 'Attack Score'.
        """
        try:
            # 1. Attempt to Decode Bytes to String (UTF-8 or ISO-8859-1)
            # Many payloads are raw bytes, so we try our best to read them.
            payload_str = payload_bytes.decode('utf-8', errors='ignore').upper()
        except:
            return "Safe", 0.0
            
        # 2. Skip empty payloads (ACK packets, handshakes)
        if len(payload_str) < 3:
            return "Safe", 0.0
            
        # 3. Calculate Score
        total_score = 0.0
        found_words = []
        
        for word, weight in self.sus_keywords.items():
            if word in payload_str:
                total_score += weight
                found_words.append(word)
                
        # 4. Final Verdict
        # If score > 1.0, we consider it malicious.
        # This handles cases where someone might just say "select" in a chat (0.8), which is safe.
        # But "UNION SELECT" (1.0 + 0.8 = 1.8) triggers an alert.
        if total_score >= 1.0:
            return "Malicious", total_score, found_words
        
        return "Safe", total_score, found_words

# ==========================================
# TEST HARNESS (Run this file directly)
# ==========================================
if __name__ == "__main__":
    print("[*] Testing Payload Engine (Probabilistic)...")
    
    nb = PayloadMonitor()
    
    print("\n[Test Case 1] Normal Traffic (HTTP GET)")
    payload = b"GET /index.html HTTP/1.1\r\nHost: google.com"
    verdict, score, words = nb.classify(payload)
    print(f"   Payload: {payload}")
    print(f"   Verdict: {verdict} | Score: {score}")
    
    print("\n[Test Case 2] SQL Injection Attack")
    payload = b"user=admin' UNION SELECT * FROM users --"
    verdict, score, words = nb.classify(payload)
    print(f"   Payload: {payload}")
    print(f"   Verdict: {verdict} | Score: {score} | Words: {words}")
    
    print("\n[Test Case 3] Path Traversal")
    payload = b"GET /../../../../etc/passwd HTTP/1.1"
    verdict, score, words = nb.classify(payload)
    print(f"   Payload: {payload}")
    print(f"   Verdict: {verdict} | Score: {score} | Words: {words}")

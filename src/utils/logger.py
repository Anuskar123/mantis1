import csv
import time
import os
import socket

# MANTIS Phase 6 & 8: Logging (Evidence Collection & Distributed Architecture)

class Logger:
    def __init__(self, filename="mantis_logs.csv"):
        self.filename = filename
        
        # Create file with header if it doesn't exist
        if not os.path.exists(self.filename):
            with open(self.filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Alert Message"])
                
    def log_alert(self, message):
        """
        Appends an alert to the CSV file.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(self.filename, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, message])
        except Exception as e:
            print(f"[!] Logging Error: {e}")

class UDPSender:
    """
    Phase 8: Distributed Logging.
    Sends alerts to a remote Dashboard/SIEM via UDP.
    """
    def __init__(self, target_ip, port=9999):
        self.target_ip = target_ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def send_log(self, message):
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            full_msg = f"[{timestamp}] {message}"
            self.sock.sendto(full_msg.encode('utf-8'), (self.target_ip, self.port))
        except Exception as e:
            print(f"[!] UDP Log Error: {e}")


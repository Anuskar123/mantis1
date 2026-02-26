import subprocess
import os

# MANTIS Phase 7: Active Defense (IPS)
# Automatically modifies Linux Firewall (iptables) to block attackers.

class ActiveDefense:
    def __init__(self):
        print("[*] Active Defense Module Initialized. Ready to engage.")
        self.blocked_ips = set()
        self.whitelist = ['127.0.0.1', '0.0.0.0'] # Never block the host itself
        
    def block_ip(self, ip_address):
        """
        Dynamically adds an iptables rule to drop all traffic from the IP.
        """
        if ip_address in self.whitelist:
            return # Safelist trigger, do not block

        if ip_address in self.blocked_ips:
            return # Already blocked
            
        print(f"[*] ACTIVATING DEFENSE: Blocking {ip_address} in Firewall...")
        
        try:
            # Command: sudo iptables -A INPUT -s <IP> -j DROP
            # We use -I INPUT 1 to insert at the TOP of the chain (Priority)
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
            
            # Check if we are root (euid 0)
            if os.geteuid() != 0:
                print(f"   [!] FAILED: Active Defense requires ROOT privileges.")
                return False
                
            subprocess.run(cmd, check=True)
            self.blocked_ips.add(ip_address)
            print(f"   [+] SUCCESS: {ip_address} has been quarantined.")
            return True
            
        except Exception as e:
            print(f"   [!] FAILED to block IP: {e}")
            return False

    def unblock_ip(self, ip_address):
        """
        Removes an IP from the blocklist.
        """
        if ip_address not in self.blocked_ips:
            return

        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            self.blocked_ips.remove(ip_address)
            print(f"   [+] UNBLOCKED: {ip_address}")
        except Exception as e:
            print(f"   [!] FAILED to unblock IP: {e}")

# Test
if __name__ == "__main__":
    print("[*] Testing Active Defense Module (Mock Mode if not Root)...")
    ips = ActiveDefense()
    # Don't actually block localhost in testing unless you want to lose connection!
    # ips.block_ip("1.2.3.4") 

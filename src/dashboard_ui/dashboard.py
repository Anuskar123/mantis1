import sys
import os
import time

# MANTIS Phase 5: CLI Dashboard (Visualization)

class Dashboard:
    def __init__(self):
        self.stats = {
            'pps': 0,
            'mean': 0.0,
            'z_score': 0.0,
            'ddos_candidate': False,
            'ddos_active': False,
        }
        self.alerts = [] # List of strings "Time - Message"
        self.max_alerts = 10

    def add_alert(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.alerts.append(f"[{timestamp}] {message}")
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0) # Keep logging window small

    def update_stats(self, pps, mean, z_score, ddos_candidate=False,
                     ddos_active=False):
        self.stats['pps'] = pps
        self.stats['mean'] = mean
        self.stats['z_score'] = z_score
        self.stats['ddos_candidate'] = bool(ddos_candidate)
        self.stats['ddos_active'] = bool(ddos_active)

    def refresh(self):
        """
        Clears the terminal and reprints the status.
        Uses ANSI escape codes for colors (Green/Red).
        """
        # Clear command for Windows vs  Linux
        os.system('cls' if os.name == 'nt' else 'clear')

        # Colors
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        RESET = '\033[0m'

        # Header
        print(f"{GREEN}================================================================{RESET}")
        print(f"{GREEN}     M.A.N.T.I.S.  -  Intelligent Threat Detection System      {RESET}")
        print(f"{GREEN}================================================================{RESET}")

        # Stats Panel
        pps = self.stats['pps']
        z = self.stats['z_score']

        # A Z-score alone is only unusual traffic. DDoS status also requires
        # the configured absolute PPS floor and sustained observations.
        sys_color = GREEN
        sys_status = "NORMAL"
        if self.stats['ddos_active']:
            sys_color = RED
            sys_status = "UNDER ATTACK (DDoS)"
        elif self.stats['ddos_candidate']:
            sys_color = YELLOW
            sys_status = "VERIFYING TRAFFIC SPIKE"

        print(f" SYSTEM STATUS : {sys_color}{sys_status}{RESET}")
        print(f" TRAFFIC VOLUME: {ppf_formatted(pps)} packets/sec")
        print(f" BASELINE MEAN : {self.stats['mean']:.2f} pps")
        print(f" Z-SCORE       : {sys_color}{z:.2f}{RESET}")
        print(f"{GREEN}----------------------------------------------------------------{RESET}")

        # Alert Log
        print(f"{CYAN} [ ALERT LOG ] {RESET}")
        if not self.alerts:
            print(f"   (No active threats detected)")
        else:
            for alert in reversed(self.alerts):
                print(f" {RED}{alert}{RESET}")

        print(f"{GREEN}================================================================{RESET}")
        print(f" Press Ctrl+C to Stop.")

def ppf_formatted(pps):
    return str(pps).rjust(5)

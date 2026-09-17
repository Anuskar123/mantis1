import os
import subprocess


class ActiveDefense:
    """Inserts iptables DROP rules for source addresses the engines flag.

    The rule is inserted with `-I INPUT 1` so it sits at the head of the chain
    and therefore wins over any ACCEPT rule already present; appending it would
    leave it unreachable on a host whose policy accepts established traffic
    early.

    Whether this class is ever asked to act is decided by the AlertDispatcher
    under the NFR-3 opt-in policy - constructing it has no side effects, so the
    sensor can always build one and simply never enable blocking.
    """

    def __init__(self, whitelist=None, dry_run=False):
        self.blocked_ips = set()
        # never block ourselves, whatever an engine decides
        self.whitelist = list(whitelist) if whitelist else ["127.0.0.1",
                                                            "0.0.0.0"]
        self.dry_run = dry_run
        self.failures = 0
        print("[*] active defense ready (whitelist: %s%s)"
              % (", ".join(self.whitelist), ", dry-run" if dry_run else ""))

    def _iptables_available(self):
        return os.name != "nt" and hasattr(os, "geteuid")

    def block_ip(self, ip):
        if ip in self.whitelist or ip in self.blocked_ips:
            return False

        if not self._iptables_available():
            print("   [!] iptables unavailable on this platform - skipping")
            return False

        if os.geteuid() != 0:
            print("   [!] can't block - need root for iptables")
            return False

        if self.dry_run:
            print("   [dry-run] would block %s" % ip)
            self.blocked_ips.add(ip)
            return True

        print("[*] blocking", ip)
        try:
            # -I INPUT 1 puts the rule at the top so it wins
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                check=True,
            )
            self.blocked_ips.add(ip)
            print("   [+] blocked")
            return True
        except Exception as e:
            self.failures += 1
            print("   [!] block failed:", e)
            return False

    def unblock_ip(self, ip):
        if ip not in self.blocked_ips:
            return False
        if self.dry_run:
            self.blocked_ips.discard(ip)
            return True
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
            )
            self.blocked_ips.discard(ip)
            print("   [+] unblocked", ip)
            return True
        except Exception as e:
            print("   [!] unblock failed:", e)
            return False

    def flush(self):
        """Remove every rule this process inserted.

        Called on shutdown so a demonstration leaves the host's firewall in the
        state it was found in, rather than requiring the operator to remember
        which addresses were dropped.
        """
        removed = 0
        for ip in list(self.blocked_ips):
            if self.unblock_ip(ip):
                removed += 1
        if removed:
            print("[*] removed %d MANTIS firewall rule(s)" % removed)
        return removed

    def active_rules(self):
        return sorted(self.blocked_ips)


if __name__ == "__main__":
    # dry-run so running this file never touches the real firewall
    d = ActiveDefense(dry_run=True)
    print(d.block_ip("10.0.0.66"))
    print(d.block_ip("127.0.0.1"), "(whitelisted)")
    print("active:", d.active_rules())
    d.flush()

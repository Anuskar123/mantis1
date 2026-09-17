#!/usr/bin/env python3
"""Alert fan-out and response policy.

The Chapter 4 class diagram shows the Sensor composing an `AlertDispatcher`
alongside the `PacketParser`. This module is that component. Previously the
fan-out was spread across two files: the sensor pushed a string onto a queue
and separately called the firewall, while `main.py` independently wrote the CSV
log and sent the UDP telemetry. Any new output surface therefore had to be
wired into two places, and an alert raised in one mode was recorded
differently from the same alert raised in another.

Centralising it here means every alert, from every engine, is:

    1. enriched once with ATT&CK context and a risk score;
    2. recorded in the forensic HTML report;
    3. written to the CSV audit trail (privacy policy applied);
    4. forwarded to the SIEM as structured JSON;
    5. pushed to whichever UI is attached;
    6. considered for an active-defence firewall drop.

Step 6 implements the FR-7 / Chapter 5.7 requirement that *any* engine may
trigger a block, subject to the NFR-3 rule that blocking is opt-in and to a
whitelist that can never be blocked.

Standard library only.
"""

import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils.mitre as mitre


class AlertDispatcher:
    """Single exit point for every alert the engines raise."""

    def __init__(self, config, reporter=None, alert_queue=None, logger=None,
                 remote=None, defense=None):
        self.config = config
        self.reporter = reporter
        self.alert_queue = alert_queue
        self.logger = logger
        self.remote = remote
        self.defense = defense

        self.total = 0
        self.by_kind = {}
        self.blocked = set()
        self._recent_alerts = {}

    # ------------------------------------------------------------------
    def dispatch(self, message, kind=None, src_ip=None, confidence=None,
                 payload=None, engine=None, response_status=False):
        """Publish one alert to every configured sink.

        `kind` may be supplied by the caller (the engine already knows what it
        detected); otherwise it is inferred from the message text.
        """
        meta = mitre.enrich(message, confidence)
        if kind:
            meta["kind"] = kind

        # Packet retransmissions and request/response fragments can carry the
        # same signature more than once. Publish one event per source/message
        # within a short window instead of inflating every downstream count.
        now = time.monotonic()
        dedup_seconds = max(
            0.0, float(getattr(self.config, "alert_dedup_seconds", 5.0)))
        dedup_key = (meta["kind"], src_ip or "", message)
        previous = self._recent_alerts.get(dedup_key)
        if (dedup_seconds > 0 and previous is not None
                and now - previous < dedup_seconds):
            meta["suppressed_duplicate"] = True
            return meta
        self._recent_alerts[dedup_key] = now
        if len(self._recent_alerts) > 2048:
            cutoff = now - max(dedup_seconds, 1.0)
            self._recent_alerts = {
                key: seen for key, seen in self._recent_alerts.items()
                if seen >= cutoff
            }

        self.total += 1
        self.by_kind[meta["kind"]] = self.by_kind.get(meta["kind"], 0) + 1

        # Decide the response before publishing so an optional status label is
        # truthful. "Blocked" is shown only after the firewall confirms that a
        # rule was inserted; otherwise the observation is merely "Flagged".
        blocked = self.maybe_block(src_ip, meta["kind"])
        meta["blocked"] = blocked
        if response_status:
            message = "%s (%s)" % (
                message, "Blocked" if blocked else "Flagged")

        # 1. forensic HTML report
        if self.reporter is not None:
            try:
                self.reporter.add_alert(message)
            except Exception as e:
                print("[!] report error:", e)

        # 2. CSV audit trail (applies the privacy policy internally)
        if self.logger is not None:
            self.logger.log_alert(message, src_ip=src_ip,
                                  engine=engine or meta["engine"],
                                  confidence=confidence, payload=payload,
                                  verdict=meta["kind"])

        # 3. structured JSON telemetry to the SIEM
        if self.remote is not None:
            self.remote.send_log(message, src_ip=src_ip,
                                 engine=engine or meta["engine"],
                                 confidence=confidence, payload=payload)

        # 4. attached UI (CLI dashboard or web bridge)
        if self.alert_queue is not None:
            self.alert_queue.put(message)
        else:
            print("\n[!!!] " + message)

        return meta

    # ------------------------------------------------------------------
    def maybe_block(self, src_ip, kind):
        """Apply the opt-in blocking policy for one source address.

        Three independent conditions must all hold before a rule is inserted,
        which is what makes the behaviour defensible under NFR-3:

            * blocking is explicitly enabled in configuration;
            * this detection kind is in the permitted block_on list;
            * the address is not whitelisted (loopback and the local host are
              whitelisted by default, so MANTIS can never firewall itself off).
        """
        if not src_ip or self.defense is None:
            return False
        if not getattr(self.config, "block_enabled", False):
            return False
        allowed = getattr(self.config, "block_on", [])
        # accept either the specific kind ("sqli") or its policy group
        # ("payload"), so a policy need not enumerate every sub-family
        if kind not in allowed and mitre.parent_kind(kind) not in allowed:
            return False
        if src_ip in getattr(self.config, "block_whitelist", []):
            print("[*] %s is whitelisted - not blocking" % src_ip)
            return False
        if src_ip in self.blocked:
            return False

        if self.defense.block_ip(src_ip):
            self.blocked.add(src_ip)
            return True
        return False

    def summary(self):
        return {"alerts": self.total, "by_kind": dict(self.by_kind),
                "blocked_ips": sorted(self.blocked)}


if __name__ == "__main__":
    from utils.config import Config

    class _FakeDefense:
        def block_ip(self, ip):
            print("   [iptables] DROP %s" % ip)
            return True

    cfg = Config()
    d = AlertDispatcher(cfg, defense=_FakeDefense())

    print("-- blocking disabled (default, NFR-3) --")
    d.dispatch("DDoS DETECTED! Z-Score: 4.2 (PPS: 9000)", src_ip="10.0.0.5",
               confidence=0.9)

    print("\n-- blocking enabled --")
    cfg.block_enabled = True
    d.dispatch("MALICIOUS PAYLOAD! Keywords: ['UNION']", src_ip="10.0.0.7",
               confidence=0.99)

    print("\n-- whitelisted source --")
    d.dispatch("PORT SCAN DETECTED! (Unique Ports: 90/sec)",
               src_ip="127.0.0.1", confidence=0.8)

    print("\n", d.summary())

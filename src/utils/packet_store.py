#!/usr/bin/env python3
"""In-memory packet history for MANTIS.

Acts like a tiny local "database" that lives entirely in RAM: a fixed-size
ring buffer of the most recently captured packets. This lets the web
dashboard show real captured traffic (source/destination, protocol, flags,
length and a raw hex dump) that the analyst can scroll through and inspect,
instead of the mock packets used before.

Zero dependencies - standard library only, consistent with the rest of
MANTIS. Thread-safe because the sensor writes from the analyzer thread while
the SIEM web server reads from HTTP handler threads.
"""

import threading
import time
from collections import deque


class PacketStore:
    def __init__(self, maxlen=5000):
        # ring buffer: when full, the oldest packet is dropped automatically
        self._packets = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

        # live traffic stats (updated once per second by the sensor)
        self.pps = 0
        self.mean = 0.0
        self.z_score = 0.0
        self.ddos_candidate = False
        self.ddos_active = False

        # cumulative counters for the whole session
        self.proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.talkers = {}          # src ip -> packet count
        self.total_seen = 0        # total packets ever recorded (not capped)

    def add(self, record):
        """Store one captured packet. `record` is a small dict of metadata."""
        with self._lock:
            self._seq += 1
            self.total_seen += 1
            record["no"] = self._seq
            self._packets.append(record)

            proto = record.get("proto", "OTHER")
            self.proto_counts[proto] = self.proto_counts.get(proto, 0) + 1

            src = record.get("src")
            if src:
                self.talkers[src] = self.talkers.get(src, 0) + 1

    def update_stats(self, pps, mean, z_score, ddos_candidate=False,
                     ddos_active=False):
        self.pps = pps
        self.mean = mean
        self.z_score = z_score
        self.ddos_candidate = bool(ddos_candidate)
        self.ddos_active = bool(ddos_active)

    def get_recent(self, limit=200, proto=None, query=None, after=0):
        """Return the newest packets first, with optional filtering.

        proto  - keep only this protocol (TCP/UDP/ICMP/OTHER)
        query  - case-insensitive substring match on src, dst, info, verdict
        after  - only return packets with a sequence number greater than this
        """
        with self._lock:
            items = list(self._packets)

        if after:
            items = [p for p in items if p["no"] > after]
        if proto and proto != "ALL":
            proto = proto.upper()
            items = [p for p in items if p.get("proto") == proto]
        if query:
            q = query.lower()
            items = [
                p for p in items
                if q in str(p.get("src", "")).lower()
                or q in str(p.get("dst", "")).lower()
                or q in str(p.get("info", "")).lower()
                or q in str(p.get("verdict", "")).lower()
            ]

        items.reverse()  # newest first
        return items[:limit]

    def all_packets(self):
        with self._lock:
            return list(self._packets)

    def top_talkers(self, n=5):
        with self._lock:
            pairs = sorted(self.talkers.items(), key=lambda kv: kv[1],
                           reverse=True)
        return [{"ip": ip, "count": c} for ip, c in pairs[:n]]

    def stats_snapshot(self):
        with self._lock:
            return {
                "pps": self.pps,
                "mean": round(self.mean, 2),
                "z_score": round(self.z_score, 2),
                "ddos_candidate": self.ddos_candidate,
                "ddos_active": self.ddos_active,
                "buffered": len(self._packets),
                "total_seen": self.total_seen,
                "capacity": self._packets.maxlen,
                "proto_counts": dict(self.proto_counts),
            }

    def clear(self):
        with self._lock:
            self._packets.clear()
            self._seq = 0
            self.total_seen = 0
            self.proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
            self.talkers = {}


def hexdump(raw, width=16):
    """Wireshark-style offset / hex / ASCII dump of raw bytes."""
    lines = []
    for off in range(0, len(raw), width):
        chunk = raw[off:off + width]
        hex_part = " ".join("%02x" % b for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%04x  %s  %s" % (off, hex_part, ascii_part))
    return "\n".join(lines)


def now_hms():
    # seconds + milliseconds, matches the packet timeline in the UI
    t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t)) + (".%03d" % int((t % 1) * 1000))


# module-level singleton shared by the sensor (writer) and SIEM (reader)
STORE = PacketStore()

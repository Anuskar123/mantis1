import hashlib
import os
import zlib

try:
    from engines.base import DetectionEngine, Verdict
except ImportError:  # allow `python engines/bloom.py` direct execution
    from base import DetectionEngine, Verdict


class BloomFilter(DetectionEngine):
    """Probabilistic set membership for IP reputation lookups.

    False positives are possible, false negatives never. A k-bit test over an
    m-bit array gives O(k) constant-time lookup independent of how many
    addresses the feed holds, which is why a reputation check can sit on the
    per-packet hot path without breaching the latency budget (NFR-1).

    The expected false-positive rate for n inserted items is

        p ~= (1 - e^(-k*n/m))^k

    and is reported by `false_positive_rate()` so the figure quoted in the
    evaluation chapter is computed rather than asserted.
    """

    name = "bloom"
    features = ("source_ip",)

    def __init__(self, size=1000, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0] * size
        self.items_added = 0        # counts insert calls, for the FP estimate

    def _hashes(self, item):
        s = str(item).encode("utf-8")
        out = []

        out.append(zlib.crc32(s) % self.size)
        out.append(int(hashlib.md5(s).hexdigest(), 16) % self.size)

        # cheap rolling hash so we have a third independent slot
        h = 0
        for ch in s:
            h = (h << 5) + ch
        out.append(h % self.size)

        # extend with salted sha1 digests if more than 3 hashes are requested
        i = 0
        while len(out) < self.hash_count:
            salted = hashlib.sha1(s + b"|" + str(i).encode()).hexdigest()
            out.append(int(salted, 16) % self.size)
            i += 1

        return out[:self.hash_count]

    def add(self, item):
        for i in self._hashes(item):
            self.bit_array[i] = 1
        self.items_added += 1

    def check(self, item):
        for i in self._hashes(item):
            if self.bit_array[i] == 0:
                return False
        return True

    # ---- threat intelligence feed --------------------------------------
    def load_feed(self, path):
        """Load a newline-separated IP blacklist ("threat intelligence feed").

        Blank lines and lines beginning with '#' are treated as comments so a
        feed can be annotated with its provenance. Returns the number of
        indicators loaded, or -1 when the file is missing.
        """
        if not path or not os.path.isfile(path):
            print("[!] threat intel feed not found: %s" % path)
            return -1

        loaded = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                indicator = line.strip()
                if not indicator or indicator.startswith("#"):
                    continue
                # tolerate "1.2.3.4,comment" and "1.2.3.4 # note" feed styles
                indicator = indicator.split(",")[0].split("#")[0].strip()
                if indicator:
                    self.add(indicator)
                    loaded += 1

        print("[*] threat intel: %d indicators loaded from %s (est. FP rate %.4f%%)"
              % (loaded, os.path.basename(path),
                 self.false_positive_rate() * 100))
        return loaded

    def false_positive_rate(self):
        """Measured saturation-based false-positive estimate: (bits_set/m)^k."""
        if not self.size:
            return 0.0
        fill = sum(self.bit_array) / float(self.size)
        return fill ** self.hash_count

    def saturation(self):
        return sum(self.bit_array) / float(self.size) if self.size else 0.0

    # ---- uniform engine interface (NFR-5) ------------------------------
    def analyse(self, source_ip):
        hit = self.check(source_ip)
        return Verdict(
            "Blacklisted" if hit else "Unknown",
            confidence=(1.0 - self.false_positive_rate()) if hit else 0.0,
            detail={"ip": source_ip, "indicators": self.items_added,
                    "saturation": round(self.saturation(), 4)},
            is_threat=hit,
        )

    def train(self, samples):
        """Insert an iterable of indicators (accepts plain IPs or (ip, label))."""
        added = 0
        for sample in samples:
            if isinstance(sample, (list, tuple)):
                if len(sample) > 1 and str(sample[1]).lower() in (
                        "normal", "safe", "benign", "0"):
                    continue          # only blacklist the malicious rows
                sample = sample[0]
            self.add(sample)
            added += 1
        print("[BF ] %d indicators (saturation %.2f%%, est. FP %.4f%%)"
              % (added, self.saturation() * 100,
                 self.false_positive_rate() * 100))
        return {"indicators": added, "saturation": self.saturation(),
                "false_positive_rate": self.false_positive_rate()}

    def export_brain(self):
        # the bit array is the model; hex-pack it so the JSON stays compact
        packed = bytes(bytearray(
            sum(bit << (7 - offset) for offset, bit in enumerate(chunk))
            for chunk in (self.bit_array[i:i + 8]
                          for i in range(0, self.size, 8))
        ))
        return {
            "size": self.size,
            "hash_count": self.hash_count,
            "items_added": self.items_added,
            "bits": packed.hex(),
        }

    def import_brain(self, data):
        if not isinstance(data, dict) or "bits" not in data:
            return False
        self.size = int(data.get("size", self.size))
        self.hash_count = int(data.get("hash_count", self.hash_count))
        self.items_added = int(data.get("items_added", 0))
        try:
            raw = bytes.fromhex(data["bits"])
        except ValueError:
            return False
        bits = []
        for byte in raw:
            for offset in range(8):
                bits.append((byte >> (7 - offset)) & 1)
        self.bit_array = bits[:self.size]
        # pad if the packed form was shorter than size
        while len(self.bit_array) < self.size:
            self.bit_array.append(0)
        print("[*] Federated Learning: Bloom restored %d indicators."
              % self.items_added)
        return True

    def reset(self):
        self.bit_array = [0] * self.size
        self.items_added = 0
        return True


if __name__ == "__main__":
    bf = BloomFilter(size=100, hash_count=3)
    for ip in ["192.168.1.100", "10.0.0.5", "172.16.0.1"]:
        bf.add(ip)
    for ip in ["192.168.1.100", "8.8.8.8", "10.0.0.5", "127.0.0.1"]:
        print(ip, "->", "BLACKLISTED" if bf.check(ip) else "clean")
    print("saturation=%.2f%% est FP=%.4f%%"
          % (bf.saturation() * 100, bf.false_positive_rate() * 100))

    snap = bf.export_brain()
    restored = BloomFilter(size=100, hash_count=3)
    restored.import_brain(snap)
    print("round trip ok:", all(restored.check(ip) for ip in
                                ["192.168.1.100", "10.0.0.5", "172.16.0.1"]))

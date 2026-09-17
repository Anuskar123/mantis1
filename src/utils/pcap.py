#!/usr/bin/env python3
"""libpcap (.pcap) reader and writer implemented from the file-format spec.

Chapter 3 commits to evaluating the sensor against "offline PCAP replays of
the CIC-IoT2023 dataset", and the zero-dependency constraint rules out Scapy,
dpkt and libpcap bindings. This module therefore implements the classic
libpcap capture-file format directly with `struct`, exactly as the sensor
already decodes Ethernet and IP headers by hand.

Two capabilities follow from it:

    * Verifiability - captures written by MANTIS open natively in Wireshark
      and tcpdump, so the claim that the sensor genuinely reads Layer 2
      frames can be independently checked by a marker rather than trusted.
    * Reproducibility - a saved capture can be replayed through the detection
      engines with no root privileges and no live attack traffic, making every
      evaluation run deterministic and repeatable.

File layout (libpcap 2.4):

    global header  24 bytes   magic, version, tz, sigfigs, snaplen, linktype
    per packet     16 bytes   ts_sec, ts_usec, incl_len, orig_len
                   + incl_len bytes of raw frame

`incl_len` may be smaller than `orig_len` when a snapshot length is applied;
Wireshark renders such frames as truncated, which is the correct
representation of a header-only capture.

Standard library only.
"""

import struct
import time

MAGIC_MICRO = 0xA1B2C3D4      # timestamps in microseconds
MAGIC_NANO = 0xA1B23C4D       # timestamps in nanoseconds
LINKTYPE_ETHERNET = 1

_GLOBAL_HEADER = "IHHiIII"    # 24 bytes
_RECORD_HEADER = "IIII"       # 16 bytes


class PcapError(Exception):
    pass


def global_header(snaplen=65535, linktype=LINKTYPE_ETHERNET, endian="<"):
    return struct.pack(endian + _GLOBAL_HEADER,
                       MAGIC_MICRO,   # magic number
                       2, 4,          # version major, minor
                       0,             # thiszone (GMT correction)
                       0,             # sigfigs (unused in practice)
                       snaplen,
                       linktype)


def record(raw, ts=None, orig_len=None, snaplen=65535, endian="<"):
    """Pack one packet record (header + data)."""
    if ts is None:
        ts = time.time()
    data = bytes(raw)[:snaplen]
    if orig_len is None:
        orig_len = len(raw)
    ts_sec = int(ts)
    ts_usec = int(round((ts - ts_sec) * 1_000_000))
    if ts_usec >= 1_000_000:       # guard against rounding to 1.0s
        ts_sec += 1
        ts_usec -= 1_000_000
    head = struct.pack(endian + _RECORD_HEADER,
                       ts_sec, ts_usec, len(data), max(orig_len, len(data)))
    return head + data


class PcapWriter:
    """Streaming writer. Usable directly or as a context manager."""

    def __init__(self, path, snaplen=65535, linktype=LINKTYPE_ETHERNET):
        self.path = path
        self.snaplen = snaplen
        self.count = 0
        self._fh = open(path, "wb")
        self._fh.write(global_header(snaplen, linktype))
        self._fh.flush()

    def write(self, raw, ts=None, orig_len=None):
        self._fh.write(record(raw, ts=ts, orig_len=orig_len,
                              snaplen=self.snaplen))
        self.count += 1

    def flush(self):
        if self._fh and not self._fh.closed:
            self._fh.flush()

    def close(self):
        if self._fh and not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class PcapReader:
    """Iterate a .pcap file yielding (timestamp, raw_bytes, original_length).

    Handles both byte orders and both microsecond and nanosecond magics, so
    captures produced by tcpdump on any host are accepted.
    """

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "rb")
        head = self._fh.read(24)
        if len(head) < 24:
            self._fh.close()
            raise PcapError("%s: truncated global header" % path)

        magic = struct.unpack("<I", head[:4])[0]
        if magic == MAGIC_MICRO:
            self.endian, self.nano = "<", False
        elif magic == MAGIC_NANO:
            self.endian, self.nano = "<", True
        elif struct.unpack(">I", head[:4])[0] == MAGIC_MICRO:
            self.endian, self.nano = ">", False
        elif struct.unpack(">I", head[:4])[0] == MAGIC_NANO:
            self.endian, self.nano = ">", True
        else:
            self._fh.close()
            raise PcapError("%s: not a pcap file (magic=0x%08x)" % (path, magic))

        (_, self.version_major, self.version_minor, self.thiszone,
         self.sigfigs, self.snaplen, self.linktype) = struct.unpack(
            self.endian + _GLOBAL_HEADER, head)

    def __iter__(self):
        divisor = 1_000_000_000.0 if self.nano else 1_000_000.0
        while True:
            head = self._fh.read(16)
            if len(head) < 16:
                return
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                self.endian + _RECORD_HEADER, head)
            data = self._fh.read(incl_len)
            if len(data) < incl_len:
                return  # truncated final record
            yield (ts_sec + ts_frac / divisor, data, orig_len)

    def close(self):
        if self._fh and not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def build_from_records(records, snaplen=65535):
    """Build a complete .pcap byte string from MANTIS packet-store records.

    Each record is the dict held in the in-memory ring buffer: a hex-encoded
    frame snapshot plus the original on-wire length. This is what the SIEM
    serves from /api/export.pcap so the analyst can open the live buffer in
    Wireshark.
    """
    out = [global_header(snaplen)]
    for item in records:
        hex_data = item.get("hex") or ""
        try:
            raw = bytes.fromhex(hex_data)
        except ValueError:
            continue
        out.append(record(raw,
                          ts=item.get("ts"),
                          orig_len=item.get("length", len(raw)),
                          snaplen=snaplen))
    return b"".join(out)


if __name__ == "__main__":
    # round-trip self-check
    frame = bytes.fromhex("ffffffffffff001122334455080045000014")
    path = "selftest.pcap"
    with PcapWriter(path, snaplen=96) as w:
        w.write(frame, ts=1700000000.123456, orig_len=1514)
    with PcapReader(path) as r:
        print("linktype=%d snaplen=%d" % (r.linktype, r.snaplen))
        for ts, data, orig in r:
            print("ts=%.6f incl=%d orig=%d match=%s"
                  % (ts, len(data), orig, data == frame))

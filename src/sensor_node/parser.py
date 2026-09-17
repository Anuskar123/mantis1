#!/usr/bin/env python3
"""Manual decoding of Layer-2 / Layer-3 / Layer-4 headers.

The Chapter 4 class diagram shows the Sensor composing a dedicated
`PacketParser`; this module is that component, lifted out of the sensor's
analyzer loop. Separating it has three practical consequences:

    * the decoder can be unit tested against synthetic frames with no root
      privileges and no live network (supporting the V-Model unit tier);
    * the offline PCAP replay tool reuses the identical decode path as the live
      sensor, so replayed results are directly comparable to live results;
    * malformed or truncated frames are rejected by explicit length checks
      instead of raising struct.error inside the analyzer thread, which would
      previously terminate that thread and silently stop all detection
      (a reliability concern under NFR-6).

FR-2 requires decoding "via manual struct.unpack (no Scapy)", which is what
happens here - every field offset is taken from the relevant RFC.

Standard library only.
"""

import socket
import struct

ETH_HEADER_LEN = 14
ETH_P_IPV4 = 0x0800        # RFC 894 EtherType for IPv4
ETH_P_VLAN = 0x8100        # IEEE 802.1Q tagged frame
VLAN_TAG_LEN = 4

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

PROTO_NAMES = {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}

# TCP flag bits, RFC 9293 section 3.1
TCP_FLAGS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
    (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
]

ICMP_TYPES = {
    0: "echo-reply", 3: "dest-unreachable", 5: "redirect",
    8: "echo-request", 11: "time-exceeded",
}


def decode_tcp_flags(flag_byte):
    names = [name for bit, name in TCP_FLAGS if flag_byte & bit]
    return ", ".join(names) if names else "-"


class PacketParser:
    """Stateless decoder: raw Ethernet frame in, normalised dict out."""

    def __init__(self):
        self.parsed = 0
        self.dropped_non_ipv4 = 0
        self.dropped_malformed = 0

    def parse(self, raw):
        """Decode one frame. Returns a dict, or None when not decodable.

        Returning None rather than raising keeps the analyzer loop simple: any
        frame that is not plaintext IPv4 TCP/UDP/ICMP is simply not analysed.
        """
        if raw is None or len(raw) < ETH_HEADER_LEN:
            self.dropped_malformed += 1
            return None

        # --- Ethernet II header (RFC 894) ---
        # "!H" already yields the EtherType in host integer form, so compare it
        # against 0x0800 directly. Passing it through ntohs() as well would
        # only produce the right answer on little-endian hosts.
        try:
            dst_mac, src_mac, eth_type = struct.unpack("!6s6sH",
                                                       raw[:ETH_HEADER_LEN])
        except struct.error:
            self.dropped_malformed += 1
            return None

        offset = ETH_HEADER_LEN

        # 802.1Q VLAN tag sits between the MACs and the real EtherType.
        # Untagged handling would drop every frame on a trunked interface.
        while eth_type == ETH_P_VLAN and len(raw) >= offset + VLAN_TAG_LEN:
            eth_type = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
            offset += VLAN_TAG_LEN

        if eth_type != ETH_P_IPV4:
            self.dropped_non_ipv4 += 1
            return None

        # --- IPv4 header (RFC 791) ---
        if len(raw) < offset + 20:
            self.dropped_malformed += 1
            return None
        try:
            iph = struct.unpack("!BBHHHBBH4s4s", raw[offset:offset + 20])
        except struct.error:
            self.dropped_malformed += 1
            return None

        version = iph[0] >> 4
        ihl = (iph[0] & 0x0F) * 4
        if version != 4 or ihl < 20:
            self.dropped_malformed += 1
            return None

        total_length = iph[2]
        ttl = iph[5]
        protocol = iph[6]
        src = socket.inet_ntoa(iph[8])
        dst = socket.inet_ntoa(iph[9])

        pkt = {
            "src": src,
            "dst": dst,
            "src_mac": src_mac.hex(),
            "dst_mac": dst_mac.hex(),
            "protocol_num": protocol,
            "proto": PROTO_NAMES.get(protocol, "OTHER"),
            "ttl": ttl,
            "ip_total_length": total_length,
            "length": len(raw),
            "sport": 0,
            "dport": 0,
            "flags": "",
            "payload": b"",
            "info": "",
        }

        t_off = offset + ihl

        if protocol == PROTO_TCP:
            if len(raw) < t_off + 20:
                self.dropped_malformed += 1
                return None
            tcph = struct.unpack("!HHLLBBHHH", raw[t_off:t_off + 20])
            data_off = (tcph[4] >> 4) * 4
            if data_off < 20:
                data_off = 20
            pkt["sport"], pkt["dport"] = tcph[0], tcph[1]
            pkt["seq"], pkt["ack"] = tcph[2], tcph[3]
            pkt["window"] = tcph[6]
            pkt["flags"] = decode_tcp_flags(tcph[5])
            pkt["payload"] = raw[t_off + data_off:]
            pkt["info"] = "%d -> %d [%s] len=%d" % (
                pkt["sport"], pkt["dport"], pkt["flags"], len(pkt["payload"]))

        elif protocol == PROTO_UDP:
            if len(raw) < t_off + 8:
                self.dropped_malformed += 1
                return None
            udph = struct.unpack("!HHHH", raw[t_off:t_off + 8])
            pkt["sport"], pkt["dport"] = udph[0], udph[1]
            pkt["payload"] = raw[t_off + 8:]
            pkt["info"] = "%d -> %d len=%d" % (
                pkt["sport"], pkt["dport"], len(pkt["payload"]))

        elif protocol == PROTO_ICMP:
            if len(raw) < t_off + 4:
                self.dropped_malformed += 1
                return None
            icmp_type, icmp_code = raw[t_off], raw[t_off + 1]
            pkt["icmp_type"], pkt["icmp_code"] = icmp_type, icmp_code
            pkt["payload"] = raw[t_off + 4:]
            pkt["info"] = "type=%d code=%d (%s)" % (
                icmp_type, icmp_code, ICMP_TYPES.get(icmp_type, "other"))

        else:
            pkt["info"] = "ip protocol %d" % protocol

        self.parsed += 1
        return pkt

    def stats(self):
        return {
            "parsed": self.parsed,
            "non_ipv4": self.dropped_non_ipv4,
            "malformed": self.dropped_malformed,
        }


# ---- frame builders, used by unit tests and the replay self-check ----------
def build_ipv4(payload, proto, src="192.168.1.10", dst="192.168.1.20", ttl=64):
    """Assemble a valid Ethernet + IPv4 frame around a Layer-4 payload."""
    eth = struct.pack("!6s6sH",
                      b"\xff\xff\xff\xff\xff\xff",
                      b"\x00\x11\x22\x33\x44\x55",
                      ETH_P_IPV4)
    total_len = 20 + len(payload)
    iph = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, total_len, 0, 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return eth + iph + payload


def build_tcp(sport=44000, dport=80, flags=0x02, data=b"", **kw):
    tcp = struct.pack("!HHLLBBHHH", sport, dport, 0, 0,
                      5 << 4, flags, 8192, 0, 0)
    return build_ipv4(tcp + data, PROTO_TCP, **kw)


def build_udp(sport=5353, dport=53, data=b"", **kw):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    return build_ipv4(udp + data, PROTO_UDP, **kw)


def build_icmp(icmp_type=8, code=0, data=b"ping", **kw):
    icmp = struct.pack("!BBH", icmp_type, code, 0)
    return build_ipv4(icmp + data, PROTO_ICMP, **kw)


if __name__ == "__main__":
    p = PacketParser()
    frames = [
        build_tcp(data=b"GET / HTTP/1.1"),
        build_udp(data=b"\x00\x01dns"),
        build_icmp(),
        b"\x00" * 10,                       # too short
        build_ipv4(b"", 47),                # GRE - valid IPv4, unusual proto
    ]
    for f in frames:
        result = p.parse(f)
        if result:
            print("%-5s %s -> %s  %s" % (result["proto"], result["src"],
                                         result["dst"], result["info"]))
        else:
            print("dropped (%d bytes)" % len(f))
    print(p.stats())

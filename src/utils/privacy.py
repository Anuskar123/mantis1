#!/usr/bin/env python3
"""Privacy and data-minimisation controls for MANTIS.

The project proposal commits, under the Data Protection Act (2018) and GDPR,
that "the packet sniffer is configured not to capture or store real world
Personally Identifiable Information (PII)". NFR-3 refines this into two
concrete engineering rules:

    * payload excerpts persisted to disk are truncated to 64 bytes;
    * identifiers may be anonymised before they reach any log.

This module enforces both. It is deliberately separate from the detection
engines: the engines see the full payload in volatile memory so that
detection accuracy is unaffected, but anything that is *persisted* (CSV audit
log, UDP telemetry, HTML report, pcap export) passes through here first.

Data minimisation applied here:
    1. length reduction   - truncate to configured excerpt size
    2. content redaction  - regex-replace credential/PII bearing tokens
    3. pseudonymisation   - optional last-octet masking of IPv4 addresses

Standard library only.
"""

import re

# Ordered most-specific first so a card number is not partly eaten by the
# generic digit-run rule.
_PII_RULES = [
    # RFC 5322-ish email address
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
     "[EMAIL_REDACTED]"),
    # 13-16 digit payment card numbers, optional spaces/dashes
    (re.compile(r"\b(?:\d[ \-]?){13,16}\b"), "[CARD_REDACTED]"),
    # password / passwd / pwd = value
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd)\s*=\s*[^&\s\"']+"),
     r"\1=[REDACTED]"),
    # api keys, tokens, secrets, session ids
    (re.compile(r"(?i)\b(api[_\-]?key|token|secret|session[_\-]?id|auth)"
                r"\s*[=:]\s*[^&\s\"']+"), r"\1=[REDACTED]"),
    # HTTP Authorization / Cookie headers
    (re.compile(r"(?i)(authorization|cookie|set-cookie)\s*:\s*[^\r\n]+"),
     r"\1: [REDACTED]"),
    # UK National Insurance number
    (re.compile(r"(?i)\b[A-Z]{2}\d{6}[A-D]\b"), "[NINO_REDACTED]"),
]


def redact(text):
    """Replace PII / credential bearing substrings with fixed markers."""
    if not text:
        return text
    for pattern, replacement in _PII_RULES:
        text = pattern.sub(replacement, text)
    return text


def payload_excerpt(payload, limit=64, privacy_mode=True):
    """Return a short, log-safe printable excerpt of a raw payload.

    payload may be bytes or str. Non-printable bytes become '.' so the excerpt
    cannot smuggle ANSI escapes or control characters into a terminal or the
    CSV audit log (log-injection defence).
    """
    if payload is None:
        return ""
    if isinstance(payload, str):
        raw = payload.encode("utf-8", errors="ignore")
    else:
        raw = bytes(payload)

    # 1. data minimisation: never keep more than the configured excerpt
    clipped = raw[:max(0, int(limit))]

    # 2. make it printable and safe to write into a CSV cell
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in clipped)

    # 3. content redaction
    if privacy_mode:
        text = redact(text)
    return text


def anonymise_ip(ip, enabled=True):
    """Mask the host portion of an IPv4 address (192.168.1.57 -> 192.168.1.0).

    Keeps the /24 network, which is all that is needed to correlate an attack
    source in an isolated lab, while removing the individual host identifier.
    Mirrors the widely used IP-anonymisation approach in web analytics.
    """
    if not enabled or not ip:
        return ip
    parts = str(ip).split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["0"])
    return ip


def truncate_hex(hex_string, limit_bytes=64):
    """Clip a hex-encoded frame snapshot to limit_bytes worth of hex chars."""
    if not hex_string:
        return ""
    return hex_string[:max(0, int(limit_bytes)) * 2]


def apply(config, src_ip=None, payload=None):
    """Convenience helper: apply the whole policy from a Config object.

    Returns (safe_ip, safe_excerpt).
    """
    safe_ip = anonymise_ip(src_ip, getattr(config, "anonymise_ips", False))
    safe_excerpt = payload_excerpt(
        payload,
        limit=getattr(config, "payload_excerpt_bytes", 64),
        privacy_mode=getattr(config, "privacy_mode", True),
    )
    return safe_ip, safe_excerpt


if __name__ == "__main__":
    samples = [
        b"GET /?user=bob@example.com&password=hunter2 HTTP/1.1",
        b"POST /pay card=4111 1111 1111 1111 api_key=sk_live_9932",
        b"Cookie: session_id=abcd1234; theme=dark",
    ]
    for s in samples:
        print(payload_excerpt(s, limit=64))
    print(anonymise_ip("192.168.1.57"))

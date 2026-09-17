#!/usr/bin/env python3
"""MITRE ATT&CK enrichment and risk scoring for MANTIS alerts.

Chapter 2 contrasts MANTIS with commercial platforms such as Snort and Wazuh.
A capability those platforms provide, and which a raw "DDoS DETECTED" string
does not, is *threat framing*: telling the analyst which adversary technique
the observation corresponds to, so the alert can be triaged against a known
kill-chain rather than read in isolation.

This module maps each MANTIS detection to its MITRE ATT&CK Enterprise
technique and tactic, and derives a bounded 0-10 risk score from the
technique's base severity plus the engine's own confidence signal. The mapping
is a static lookup table, so enrichment costs one dictionary hit per alert and
adds no measurable latency (preserving NFR-1).

Reference: MITRE ATT&CK Enterprise Matrix v14 (attack.mitre.org).
Standard library only.
"""

import re

# detection kind -> ATT&CK technique metadata
TECHNIQUES = {
    "ddos": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "severity": "CRITICAL",
        "base_score": 8.5,
        "engine": "Z-Score (statistical)",
    },
    "scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "severity": "MEDIUM",
        "base_score": 5.0,
        "engine": "KNN (behavioural)",
    },
    "sqli": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "severity": "HIGH",
        "base_score": 9.0,
        "engine": "Naive Bayes (payload)",
    },
    "xss": {
        "id": "T1059.007",
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "severity": "HIGH",
        "base_score": 7.5,
        "engine": "Naive Bayes (payload)",
    },
    "lfi": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "severity": "HIGH",
        "base_score": 7.0,
        "engine": "Naive Bayes (payload)",
    },
    "payload": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "severity": "HIGH",
        "base_score": 8.0,
        "engine": "Naive Bayes (payload)",
    },
    "blacklist": {
        "id": "T1071",
        "name": "Application Layer Protocol (known-bad infrastructure)",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "severity": "HIGH",
        "base_score": 7.5,
        "engine": "Bloom Filter (reputation)",
    },
    "anomaly": {
        "id": "T1071",
        "name": "Anomalous Traffic Profile (behavioural drift)",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "severity": "MEDIUM",
        "base_score": 4.5,
        "engine": "K-Means (clustering)",
    },
    "unknown": {
        "id": "N/A",
        "name": "Uncategorised Observation",
        "tactic": "Unknown",
        "tactic_id": "N/A",
        "severity": "INFO",
        "base_score": 1.0,
        "engine": "n/a",
    },
}

# Specific payload families roll up to the "payload" category, so a policy
# written as block_on=["payload"] covers sqli, xss and lfi without having to
# enumerate every sub-family.
KIND_GROUPS = {
    "sqli": "payload",
    "xss": "payload",
    "lfi": "payload",
    "payload": "payload",
}


def parent_kind(kind):
    """Return the policy group a detection kind belongs to."""
    return KIND_GROUPS.get(kind, kind)


# payload keyword -> more specific attack family, checked before generic
_PAYLOAD_FAMILIES = [
    (re.compile(r"(?i)UNION|SELECT|OR 1=1|SLEEP|DROP|INSERT|UPDATE"), "sqli"),
    (re.compile(r"(?i)SCRIPT|ALERT\(|ONERROR|<IMG"), "xss"),
    (re.compile(r"(?i)/ETC/PASSWD|\.\./|/PROC/SELF"), "lfi"),
]


def classify_kind(message):
    """Infer the detection kind from a MANTIS alert string."""
    if not message:
        return "unknown"
    upper = message.upper()

    if "DDOS" in upper or "Z-SCORE" in upper:
        return "ddos"
    if "SCAN" in upper:
        return "scan"
    if "BLACKLIST" in upper:
        return "blacklist"
    if "PAYLOAD" in upper or "MALICIOUS" in upper:
        for pattern, family in _PAYLOAD_FAMILIES:
            if pattern.search(message):
                return family
        return "payload"
    if "ANOMALY" in upper or "CLUSTER" in upper:
        return "anomaly"
    return "unknown"


def risk_score(kind, confidence=None):
    """Blend the technique base score with engine confidence -> 0.0..10.0.

    The technique's base score is the ceiling for that class of attack; engine
    confidence scales it down to 70% at worst. A low-confidence hit on a severe
    technique therefore still outranks a confident low-severity hit, and no
    score saturates at the top of the scale.
    """
    base = TECHNIQUES.get(kind, TECHNIQUES["unknown"])["base_score"]
    if confidence is None:
        return round(base, 1)
    try:
        c = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        return round(base, 1)
    scaled = base * (0.7 + 0.3 * c)
    return round(max(0.0, min(10.0, scaled)), 1)


def enrich(message, confidence=None):
    """Return full ATT&CK context for an alert message.

    The returned dict is embedded in the CSV audit log, the JSON UDP telemetry
    frame, the web dashboard and the forensic HTML report, so every output
    surface carries the same threat framing.
    """
    kind = classify_kind(message)
    meta = TECHNIQUES.get(kind, TECHNIQUES["unknown"])
    return {
        "kind": kind,
        "technique_id": meta["id"],
        "technique": meta["name"],
        "tactic": meta["tactic"],
        "tactic_id": meta["tactic_id"],
        "severity": meta["severity"],
        "engine": meta["engine"],
        "risk_score": risk_score(kind, confidence),
        "reference": ("https://attack.mitre.org/techniques/%s/"
                      % meta["id"].replace(".", "/")
                      if meta["id"] != "N/A" else ""),
    }


if __name__ == "__main__":
    for m in [
        "DDoS DETECTED! Z-Score: 4.21 (PPS: 8500)",
        "PORT SCAN DETECTED! (Unique Ports: 44/sec)",
        "MALICIOUS PAYLOAD! Keywords: ['UNION', 'SELECT']",
        "MALICIOUS PAYLOAD! Keywords: ['SCRIPT', 'ALERT(']",
        "BLACKLISTED IP DETECTED: 10.0.0.66 (Flagged)",
        "ANOMALY DETECTED (Cluster 2)! Suspicious activity.",
    ]:
        e = enrich(m, confidence=0.95)
        print("%-9s %-10s %-38s risk=%.1f" %
              (e["kind"], e["technique_id"], e["technique"], e["risk_score"]))

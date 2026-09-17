import csv
import json
import os


NORMAL = {"normal", "benign", "0", "background", "safe"}
SCAN = {"scan", "portscan", "port_scan", "recon", "reconnaissance"}
ATTACK = {"ddos", "dos", "flood", "synflood", "udpflood",
          "attack", "malicious", "1", "anomaly"}


class DatasetError(Exception):
    pass


def normalise_label(raw):
    if raw is None:
        return "Normal"
    k = str(raw).strip().lower()
    compact = k.replace("-", "").replace("_", "").replace(" ", "")
    if k in NORMAL:
        return "Normal"
    if (k in SCAN or "portscan" in compact
            or compact.startswith("recon")):
        return "Scan"
    if k in {"malicious", "sqli", "xss", "lfi", "rce", "payload"}:
        return "Malicious"
    if k in ATTACK:
        return "Attack"
    return raw.strip().capitalize() or "Normal"


def _open(path):
    if not os.path.isfile(path):
        raise DatasetError("file not found: " + path)
    return open(path, "r", newline="", encoding="utf-8", errors="ignore")


def load_knn_csv(path):
    out = []
    with _open(path) as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            raise DatasetError(path + ": empty header")
        h = {c.lower().strip(): c for c in r.fieldnames}
        for need in ("unique_ports", "packet_count", "label"):
            if need not in h:
                raise DatasetError(path + ": missing column " + need)
        for i, row in enumerate(r, start=2):
            try:
                ports = int(float(row[h["unique_ports"]]))
                pkts = int(float(row[h["packet_count"]]))
            except (TypeError, ValueError):
                raise DatasetError("%s:%d bad number" % (path, i))
            out.append([ports, pkts, normalise_label(row[h["label"]])])
    if not out:
        raise DatasetError(path + ": no rows")
    return out


def load_payload_csv(path):
    out = []
    with _open(path) as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            raise DatasetError(path + ": empty header")
        h = {c.lower().strip(): c for c in r.fieldnames}
        if "payload" not in h or "label" not in h:
            raise DatasetError(path + ": need payload,label columns")
        for row in r:
            out.append((row[h["payload"]] or "",
                        normalise_label(row[h["label"]])))
    if not out:
        raise DatasetError(path + ": no rows")
    return out


def load_kmeans_csv(path, include_labels=False):
    out = []
    with _open(path) as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            raise DatasetError(path + ": empty header")
        h = {c.lower().strip(): c for c in r.fieldnames}
        if "pps" not in h or "unique_ports" not in h:
            raise DatasetError(path + ": kmeans CSV requires 'pps' and 'unique_ports' columns.")
        label_col = h.get("label")
        for i, row in enumerate(r, start=2):
            try:
                point = [float(row[h["pps"]]),
                         float(row[h["unique_ports"]])]
            except (TypeError, ValueError):
                raise DatasetError("%s:%d bad number" % (path, i))
            if include_labels:
                label = normalise_label(row[label_col]) if label_col else "Normal"
                out.append((point, label))
            else:
                out.append(point)
    if not out:
        raise DatasetError(path + ": no rows")
    return out


def load_zscore_csv(path):
    out = []
    with _open(path) as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            raise DatasetError(path + ": empty header")
        h = {c.lower().strip(): c for c in r.fieldnames}
        if "pps" not in h or "label" not in h:
            raise DatasetError(path + ": need pps,label columns")
        for i, row in enumerate(r, start=2):
            try:
                value = float(row[h["pps"]])
            except (TypeError, ValueError):
                raise DatasetError("%s:%d bad number" % (path, i))
            if value < 0:
                raise DatasetError("%s:%d negative pps" % (path, i))
            out.append((value, normalise_label(row[h["label"]])))
    if not out:
        raise DatasetError(path + ": no rows")
    return out


def load_bloom_csv(path):
    out = []
    with _open(path) as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            raise DatasetError(path + ": empty header")
        h = {c.lower().strip(): c for c in r.fieldnames}
        ip_key = "ip" if "ip" in h else "src_ip" if "src_ip" in h else None
        if not ip_key or "label" not in h:
            raise DatasetError(path + ": need ip,label columns")
        for row in r:
            indicator = (row[h[ip_key]] or "").strip()
            if not indicator:
                continue
            out.append((indicator, normalise_label(row[h["label"]])))
    if not out:
        raise DatasetError(path + ": no rows")
    return out


def load_cic_iot2023(path):
    # MANTIS KNN consumes one-second aggregate counts, not raw port numbers.
    # A previous loader incorrectly substituted "Dst Port" for
    # "unique_ports" and labeled every attack family as Scan. That produced
    # invalid training points such as [0 ports, packets, Scan].
    knn_rows, km_rows = [], []
    with _open(path) as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            raise DatasetError(path + ": empty header")
        cols = {c.strip().lower(): c for c in r.fieldnames}
        label_col = cols.get("label") or cols.get("attack")
        pkts_col = (cols.get("tot fwd pkts") or cols.get("totfwdpkts")
                    or cols.get("tot sum") or cols.get("packet_count")
                    or cols.get("packets"))
        ports_col = cols.get("unique_ports")
        if not label_col or not pkts_col:
            raise DatasetError(path + ": need Label + packet count col")
        if not ports_col:
            raise DatasetError(
                path + ": CIC rows must be pre-aggregated with a "
                "'unique_ports' column; 'Dst Port' is a port number, not a "
                "count of scanned ports")
        for row in r:
            try:
                pkts = int(float(row[pkts_col] or 0))
            except ValueError:
                continue
            try:
                ports = int(float(row[ports_col] or 0))
            except ValueError:
                continue
            if pkts < 0 or ports < 0 or ports > pkts:
                continue
            lbl = normalise_label(row[label_col])
            # This is a scan-vs-not-scan classifier. DDoS, payload attacks,
            # and other attack families are negative examples, not scans.
            tag = "Scan" if lbl == "Scan" else "Normal"
            knn_rows.append([ports, pkts, tag])
            km_rows.append([float(pkts), float(ports)])
    if not knn_rows:
        raise DatasetError(path + ": no usable rows")
    return {"knn": knn_rows, "kmeans": km_rows}


def load_json(path):
    if not os.path.isfile(path):
        raise DatasetError("file not found: " + path)
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise DatasetError(path + ": bad JSON (%s)" % e)

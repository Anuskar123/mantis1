#!/usr/bin/env python3
"""Common contract shared by every MANTIS detection engine.

NFR-5 (Maintainability) requires that "all detection engine classes shall
implement a uniform public interface exposing analyse(), train(),
export_brain(), and import_brain() methods", and the Chapter 4 class diagram
shows the sensor composing an abstract DetectionEngine rather than five
unrelated classes. This module is that abstraction.

The benefit is concrete rather than cosmetic: because the sensor and the
evaluation harness both talk to `analyse()` and `train()`, a sixth engine can
be added by writing one subclass, with no change to the sensor orchestrator,
the evaluator, or the brain serialisation code.

Each engine keeps its original domain-specific method (`classify`,
`calculate_baseline`, `check`) so existing callers and unit tests are
unaffected; `analyse()` is a thin uniform adapter over that method.

Standard library only.
"""


class Verdict:
    """Uniform result returned by every engine's analyse() method.

    label      - engine specific verdict string ("Scan", "Malicious", "DDoS")
    confidence - 0.0..1.0 where available, else None
    detail     - engine specific extras (matched keywords, neighbours, z value)
    is_threat  - True when the label represents an attack for this engine
    """

    __slots__ = ("label", "confidence", "detail", "is_threat")

    def __init__(self, label, confidence=None, detail=None, is_threat=False):
        self.label = label
        self.confidence = confidence
        self.detail = detail if detail is not None else {}
        self.is_threat = is_threat

    def as_dict(self):
        return {
            "label": self.label,
            "confidence": self.confidence,
            "detail": self.detail,
            "is_threat": self.is_threat,
        }

    def __repr__(self):
        conf = "n/a" if self.confidence is None else "%.3f" % self.confidence
        return "<Verdict %s conf=%s threat=%s>" % (
            self.label, conf, self.is_threat)


class DetectionEngine:
    """Abstract base class for the five MANTIS engines."""

    name = "engine"
    # what this engine consumes, used for documentation and the evaluator
    features = ()

    def analyse(self, *args, **kwargs):
        """Evaluate one observation and return a Verdict."""
        raise NotImplementedError(
            "%s must implement analyse()" % type(self).__name__)

    def train(self, samples):
        """Learn from an iterable of labelled samples. Returns a summary dict.

        Engines that are purely online (Z-Score, Bloom) override this with
        their own accumulation behaviour.
        """
        raise NotImplementedError(
            "%s must implement train()" % type(self).__name__)

    def export_brain(self):
        """Serialise learned state to a JSON-safe dict."""
        return {}

    def import_brain(self, data):
        """Restore learned state from export_brain() output."""
        return False

    def reset(self):
        """Drop learned state, returning the engine to its seeded defaults."""
        return False

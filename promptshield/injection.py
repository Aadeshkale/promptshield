"""
Prompt Injection Detection Scanner.

Multi-layer defense-in-depth scanner for detecting prompt injection attacks.
Runs as a parallel pipeline alongside the secret detection pipeline.

Layers:
  1. Pattern matching (fast, <1ms)
  2. Entropy analysis (fast, <1ms)
  3. ML classifier (optional, ~50ms, requires transformers)
"""

import logging
import math
from collections import Counter
from typing import List

from promptshield.detectors.injection import InjectionPatternDetector
from promptshield.classifiers.injection import InjectionMLClassifier
from promptshield.context import ContextEnricher
from promptshield.policies.default import DefaultPolicy
from promptshield.redactors.default import DefaultRedactor
from promptshield.models import InjectionResult

logger = logging.getLogger(__name__)


LAYER_WEIGHTS = {
    "pattern": 0.25,
    "entropy": 0.15,
    "ml": 0.60,
}

DEFAULT_THRESHOLD = 0.7


class InjectionScanner:
    """
    Multi-layer prompt injection scanner.

    Combines regex patterns, entropy analysis, and optional ML classification
    to detect prompt injection attempts.
    """

    def __init__(self, threshold=DEFAULT_THRESHOLD, mode="flag"):
        self.threshold = threshold
        self.mode = mode
        self.detector = InjectionPatternDetector()
        self.enricher = ContextEnricher()
        self.ml_classifier = InjectionMLClassifier()
        self.policy = DefaultPolicy()
        self.redactor = DefaultRedactor()

        logger.info(
            "InjectionScanner initialized (threshold=%.2f, mode=%s, ml_available=%s)",
            threshold, mode, self.ml_classifier.is_available(),
        )

    def scan(self, text):
        scores = {}
        patterns_matched = []

        logger.debug("Injection scan start (%d chars)", len(text))

        # Layer 1: Pattern matching
        pattern_score = self._check_patterns(text, patterns_matched)
        scores["pattern"] = pattern_score
        logger.debug("Layer 1 (pattern): score=%.4f, patterns=%s", pattern_score, patterns_matched)

        # Layer 2: Entropy analysis
        entropy_score = self._check_entropy(text)
        scores["entropy"] = entropy_score
        logger.debug("Layer 2 (entropy): score=%.4f", entropy_score)

        # Layer 3: ML classification (if available)
        ml_available = self.ml_classifier.is_available()
        if ml_available:
            ml_score = self.ml_classifier.classify(text)
            scores["ml"] = ml_score
            logger.debug("Layer 3 (ML): score=%.4f", ml_score)
        else:
            scores["ml"] = 0.0
            logger.debug("Layer 3 (ML): unavailable, score=0.0")

        # Weighted ensemble (redistribute ML weight when unavailable)
        if ml_available:
            weights = LAYER_WEIGHTS
        else:
            ml_weight = LAYER_WEIGHTS["ml"]
            remaining = 1.0 - ml_weight
            weights = {
                "pattern": LAYER_WEIGHTS["pattern"] + ml_weight * LAYER_WEIGHTS["pattern"] / (LAYER_WEIGHTS["pattern"] + LAYER_WEIGHTS["entropy"]),
                "entropy": LAYER_WEIGHTS["entropy"] + ml_weight * LAYER_WEIGHTS["entropy"] / (LAYER_WEIGHTS["pattern"] + LAYER_WEIGHTS["entropy"]),
                "ml": 0.0,
            }

        total_score = sum(
            scores[layer] * weight
            for layer, weight in weights.items()
        )

        blocked = total_score >= self.threshold

        logger.debug(
            "Injection scan complete: threat=%.4f, blocked=%s (threshold=%.2f, weights=%s)",
            total_score, blocked, self.threshold,
            {k: round(v, 2) for k, v in weights.items()},
        )

        return InjectionResult(
            threat_score=round(total_score, 4),
            blocked=blocked,
            scores={k: round(v, 4) for k, v in scores.items()},
            patterns_matched=patterns_matched,
            action=self.mode,
        )

    def _check_patterns(self, text, patterns_matched):
        candidates = self.detector.detect(text)
        if not candidates:
            return 0.0

        max_score = 0.0
        for candidate in candidates:
            category = candidate.pattern_name.replace("INJECTION_", "").lower()
            if category not in patterns_matched:
                patterns_matched.append(category)

            # Score based on pattern category
            if "delimiter" in category:
                score = 0.85
            elif "exfil" in category:
                score = 0.90
            elif "system_extraction" in category:
                score = 0.80
            elif "role_hijack" in category or "developer" in category:
                score = 0.75
            elif "instruction_override" in category:
                score = 0.70
            elif "new_instructions" in category:
                score = 0.65
            elif "encoded" in category:
                score = 0.40
            else:
                score = 0.50

            max_score = max(max_score, score)

        return min(max_score, 1.0)

    def _check_entropy(self, text):
        # Check for high-entropy segments that might be encoded payloads
        words = text.split()
        if not words:
            return 0.0

        high_entropy_count = 0
        for word in words:
            if len(word) < 20:
                continue
            entropy = self._shannon_entropy(word)
            if entropy > 5.1:
                high_entropy_count += 1

        if high_entropy_count == 0:
            return 0.0

        return min(high_entropy_count / max(len(words), 1) * 2, 1.0)

    def _shannon_entropy(self, text):
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

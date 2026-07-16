"""
Stage 3: Classification.

Classifiers decide what each candidate is based on pattern + context + entropy.
"""

import math
from abc import ABC, abstractmethod
from collections import Counter

from promptshield.models import Candidate, Context, Finding


class BaseClassifier(ABC):

    @abstractmethod
    def classify(self, candidate: Candidate, context: Context) -> Finding:
        """Classify a candidate into a Finding, or return None."""
        pass

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        counter = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

    def _context_boost(self, context: Context, keywords: list) -> float:
        context_text = (context.preceding + context.following + context.line).lower()
        if any(kw in context_text for kw in keywords):
            return 0.30
        return 0.0

    def _entropy_boost(self, value: str) -> float:
        entropy = self._calculate_entropy(value)
        return min(entropy / 20, 0.20)

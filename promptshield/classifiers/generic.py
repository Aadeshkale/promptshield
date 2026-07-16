"""
Generic Token Classifier.

Catches remaining tokens that don't match provider-specific classifiers.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class GenericClassifier(BaseClassifier):

    PATTERNS = {
        "ya29": {
            "secret_type": "GENERIC_OAUTH_TOKEN",
            "base_confidence": 0.30,
            "base_specificity": 20,
            "replacement": "<GENERIC_OAUTH_TOKEN>",
        },
        "1//": {
            "secret_type": "GENERIC_REFRESH_TOKEN",
            "base_confidence": 0.30,
            "base_specificity": 20,
            "replacement": "<GENERIC_REFRESH_TOKEN>",
        },
        "AIza": {
            "secret_type": "GENERIC_API_KEY",
            "base_confidence": 0.30,
            "base_specificity": 20,
            "replacement": "<GENERIC_API_KEY>",
        },
        "GOCSPX": {
            "secret_type": "GENERIC_OAUTH_SECRET",
            "base_confidence": 0.30,
            "base_specificity": 20,
            "replacement": "<GENERIC_OAUTH_SECRET>",
        },
        "SECRET_KEY": {
            "secret_type": "GENERIC_SECRET",
            "base_confidence": 0.30,
            "base_specificity": 20,
            "replacement": "<GENERIC_SECRET>",
        },
        "SESSION_TOKEN": {
            "secret_type": "GENERIC_TOKEN",
            "base_confidence": 0.30,
            "base_specificity": 20,
            "replacement": "<GENERIC_TOKEN>",
        },
    }

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        confidence = pattern_info["base_confidence"]
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="generic",
            secret_type=pattern_info["secret_type"],
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement=pattern_info["replacement"],
            confidence=min(confidence, 1.0),
            specificity=pattern_info["base_specificity"],
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

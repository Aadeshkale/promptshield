"""
AWS Classifier.

Classifies AWS-related candidates based on pattern + context.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class AWSClassifier(BaseClassifier):

    PATTERNS = {
        "AKIA": {
            "secret_type": "AWS_ACCESS_KEY",
            "base_confidence": 0.50,
            "base_specificity": 100,
            "replacement": "<AWS_ACCESS_KEY>",
        },
        "ASIA": {
            "secret_type": "AWS_TEMPORARY_KEY",
            "base_confidence": 0.50,
            "base_specificity": 100,
            "replacement": "<AWS_TEMPORARY_KEY>",
        },
        "SECRET_KEY": {
            "secret_type": "AWS_SECRET_KEY",
            "base_confidence": 0.50,
            "base_specificity": 100,
            "replacement": "<AWS_SECRET_KEY>",
        },
        "SESSION_TOKEN": {
            "secret_type": "AWS_SESSION_TOKEN",
            "base_confidence": 0.50,
            "base_specificity": 100,
            "replacement": "<AWS_SESSION_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "aws", "amazon", "access_key", "secret_key",
        "session_token", "credentials", "credentials",
    ]

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        confidence = pattern_info["base_confidence"]
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="aws",
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

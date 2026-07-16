"""
OAuth/JWT Classifier.

Classifies generic OAuth and JWT candidates based on pattern + context.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class OAuthClassifier(BaseClassifier):

    PATTERNS = {
        "eyJ": {
            "secret_type": "JWT_TOKEN",
            "base_confidence": 0.50,
            "base_specificity": 70,
            "replacement": "<JWT_TOKEN>",
        },
        "Bearer": {
            "secret_type": "BEARER_TOKEN",
            "base_confidence": 0.30,
            "base_specificity": 30,
            "replacement": "<BEARER_TOKEN>",
        },
        "OAuth": {
            "secret_type": "OAUTH_TOKEN",
            "base_confidence": 0.30,
            "base_specificity": 30,
            "replacement": "<OAUTH_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = ["authorization", "bearer", "oauth", "token"]

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
            detector="oauth",
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

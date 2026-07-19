"""
PII Classifier.

Classifies PII candidates (email, phone, SSN, credit card, IP, address).
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class PIIClassifier(BaseClassifier):

    PATTERNS = {
        "EMAIL_ADDRESS": {
            "secret_type": "EMAIL_ADDRESS",
            "base_confidence": 0.70,
            "base_specificity": 60,
            "replacement": "<EMAIL>",
        },
        "PHONE_NUMBER": {
            "secret_type": "PHONE_NUMBER",
            "base_confidence": 0.65,
            "base_specificity": 55,
            "replacement": "<PHONE>",
        },
        "SSN": {
            "secret_type": "SSN",
            "base_confidence": 0.90,
            "base_specificity": 95,
            "replacement": "<SSN>",
        },
        "CREDIT_CARD": {
            "secret_type": "CREDIT_CARD",
            "base_confidence": 0.85,
            "base_specificity": 90,
            "replacement": "<CREDIT_CARD>",
        },
        "IP_ADDRESS": {
            "secret_type": "IP_ADDRESS",
            "base_confidence": 0.50,
            "base_specificity": 30,
            "replacement": "<IP_ADDRESS>",
        },
        "IPV6_ADDRESS": {
            "secret_type": "IPV6_ADDRESS",
            "base_confidence": 0.50,
            "base_specificity": 30,
            "replacement": "<IPV6_ADDRESS>",
        },
        "US_STREET_ADDRESS": {
            "secret_type": "US_STREET_ADDRESS",
            "base_confidence": 0.60,
            "base_specificity": 50,
            "replacement": "<ADDRESS>",
        },
    }

    def classify(self, candidate, context):
        pattern_info = self.PATTERNS.get(candidate.pattern_name)
        if not pattern_info:
            return None

        confidence = pattern_info["base_confidence"]

        return Finding(
            detector="pii",
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

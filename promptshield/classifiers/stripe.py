"""
Stripe Classifier.

Classifies Stripe secret key, publishable key, and webhook secret candidates.
Publishable keys require context keywords (pk_live/pk_test pattern is ambiguous).
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class StripeClassifier(BaseClassifier):

    PATTERNS = {
        "STRIPE_SECRET_KEY": {
            "secret_type": "STRIPE_SECRET_KEY",
            "base_confidence": 0.50,
            "base_specificity": 100,
            "replacement": "<STRIPE_SECRET_KEY>",
        },
        "STRIPE_PUBLISHABLE_KEY": {
            "secret_type": "STRIPE_PUBLISHABLE_KEY",
            "base_confidence": 0.40,
            "base_specificity": 80,
            "replacement": "<STRIPE_PUBLISHABLE_KEY>",
        },
        "STRIPE_WEBHOOK_SECRET": {
            "secret_type": "STRIPE_WEBHOOK_SECRET",
            "base_confidence": 0.50,
            "base_specificity": 100,
            "replacement": "<STRIPE_WEBHOOK_SECRET>",
        },
    }

    CONTEXT_KEYWORDS = [
        "stripe", "payment", "sk_live", "pk_live", "whsec",
        "API key", "webhook",
    ]

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        if candidate.pattern_name == "STRIPE_PUBLISHABLE_KEY":
            context_text = (context.preceding + context.following + context.line).lower()
            has_context = any(kw in context_text for kw in self.CONTEXT_KEYWORDS)
            if not has_context:
                return None

        confidence = pattern_info["base_confidence"]
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="stripe",
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

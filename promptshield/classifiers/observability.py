"""
Observability Classifier.

Classifies Datadog, New Relic, and Sentry candidates.
Datadog keys require context keywords (32/40-char patterns are ambiguous).
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class ObservabilityClassifier(BaseClassifier):

    PATTERNS = {
        "DATADOG_API_KEY": {
            "secret_type": "DATADOG_API_KEY",
            "base_confidence": 0.30,
            "base_specificity": 50,
            "replacement": "<DATADOG_API_KEY>",
        },
        "DATADOG_APP_KEY": {
            "secret_type": "DATADOG_APP_KEY",
            "base_confidence": 0.30,
            "base_specificity": 50,
            "replacement": "<DATADOG_APP_KEY>",
        },
        "NEW_RELIC_API_KEY": {
            "secret_type": "NEW_RELIC_API_KEY",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<NEW_RELIC_API_KEY>",
        },
        "SENTRY_DSN": {
            "secret_type": "SENTRY_DSN",
            "base_confidence": 0.70,
            "base_specificity": 100,
            "replacement": "<SENTRY_DSN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "datadog", "dd_api", "dd_app", "newrelic", "new relic",
        "sentry", "apm", "monitoring", "observability",
    ]

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        if candidate.pattern_name in ("DATADOG_API_KEY", "DATADOG_APP_KEY"):
            context_text = (context.preceding + context.following + context.line).lower()
            has_context = any(kw in context_text for kw in self.CONTEXT_KEYWORDS)
            if not has_context:
                return None

        confidence = pattern_info["base_confidence"]
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="observability",
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

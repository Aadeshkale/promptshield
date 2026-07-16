"""
Slack Classifier.

Classifies Slack bot token, user token, and webhook candidates.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class SlackClassifier(BaseClassifier):

    PATTERNS = {
        "SLACK_BOT_TOKEN": {
            "secret_type": "SLACK_BOT_TOKEN",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<SLACK_BOT_TOKEN>",
        },
        "SLACK_USER_TOKEN": {
            "secret_type": "SLACK_USER_TOKEN",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<SLACK_USER_TOKEN>",
        },
        "SLACK_WEBHOOK": {
            "secret_type": "SLACK_WEBHOOK",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<SLACK_WEBHOOK_URL>",
        },
    }

    CONTEXT_KEYWORDS = [
        "slack", "hooks", "xoxb", "xoxp", "bot token", "webhook",
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
            detector="slack",
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

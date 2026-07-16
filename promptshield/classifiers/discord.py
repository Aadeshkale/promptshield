"""
Discord Classifier.

Classifies Discord bot token candidates.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class DiscordClassifier(BaseClassifier):

    PATTERNS = {
        "DISCORD_BOT_TOKEN": {
            "secret_type": "DISCORD_BOT_TOKEN",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<DISCORD_BOT_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "discord", "bot", "token", "discord_bot",
    ]

    def classify(self, candidate, context):
        if candidate.pattern_name != "DISCORD_BOT_TOKEN":
            return None

        confidence = 0.60
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="discord",
            secret_type="DISCORD_BOT_TOKEN",
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement="<DISCORD_BOT_TOKEN>",
            confidence=min(confidence, 1.0),
            specificity=100,
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

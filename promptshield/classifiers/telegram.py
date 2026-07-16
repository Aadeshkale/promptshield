from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class TelegramClassifier(BaseClassifier):

    PATTERNS = {
        "TELEGRAM_BOT_TOKEN": {
            "secret_type": "TELEGRAM_BOT_TOKEN",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<TELEGRAM_BOT_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "telegram", "bot", "tg", "5845283892",
    ]

    def classify(self, candidate, context):
        if candidate.pattern_name != "TELEGRAM_BOT_TOKEN":
            return None

        confidence = 0.60
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="telegram",
            secret_type="TELEGRAM_BOT_TOKEN",
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement="<TELEGRAM_BOT_TOKEN>",
            confidence=min(confidence, 1.0),
            specificity=100,
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

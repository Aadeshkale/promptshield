from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class TwilioClassifier(BaseClassifier):

    PATTERNS = {
        "TWILIO_ACCOUNT_SID": {
            "secret_type": "TWILIO_ACCOUNT_SID",
            "base_confidence": 0.50,
            "base_specificity": 90,
            "replacement": "<TWILIO_ACCOUNT_SID>",
        },
        "TWILIO_AUTH_TOKEN": {
            "secret_type": "TWILIO_AUTH_TOKEN",
            "base_confidence": 0.50,
            "base_specificity": 95,
            "replacement": "<TWILIO_AUTH_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "twilio", "sms", "sms", "account_sid", "auth_token",
        "phone", "send_sms",
    ]

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        context_text = (context.preceding + context.following + context.line).lower()
        has_context = any(kw in context_text for kw in self.CONTEXT_KEYWORDS)
        if not has_context:
            return None

        confidence = pattern_info["base_confidence"]
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="twilio",
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

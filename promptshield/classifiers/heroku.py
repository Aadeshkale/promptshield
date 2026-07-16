"""
Heroku Classifier.

Classifies Heroku API key candidates.
Requires context keywords (UUID format is ambiguous).
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class HerokuClassifier(BaseClassifier):

    PATTERNS = {
        "HEROKU_API_KEY": {
            "secret_type": "HEROKU_API_KEY",
            "base_confidence": 0.30,
            "base_specificity": 50,
            "replacement": "<HEROKU_API_KEY>",
        },
    }

    CONTEXT_KEYWORDS = [
        "heroku", "heroku_api", "api_key", "heroku_auth",
    ]

    def classify(self, candidate, context):
        if candidate.pattern_name != "HEROKU_API_KEY":
            return None

        context_text = (context.preceding + context.following + context.line).lower()
        has_context = any(kw in context_text for kw in self.CONTEXT_KEYWORDS)
        if not has_context:
            return None

        confidence = 0.30
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="heroku",
            secret_type="HEROKU_API_KEY",
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement="<HEROKU_API_KEY>",
            confidence=min(confidence, 1.0),
            specificity=50,
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

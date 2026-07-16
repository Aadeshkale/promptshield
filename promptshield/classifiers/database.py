"""
Database Connection String Classifier.

Classifies database connection string candidates containing embedded credentials.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class DatabaseClassifier(BaseClassifier):

    PATTERNS = {
        "DATABASE_CONNECTION_STRING": {
            "secret_type": "DATABASE_CONNECTION_STRING",
            "base_confidence": 0.70,
            "base_specificity": 90,
            "replacement": "<DATABASE_CONNECTION_STRING>",
        },
    }

    CONTEXT_KEYWORDS = [
        "database", "db", "postgres", "mysql", "mongodb",
        "connection", "url", "redis",
    ]

    def classify(self, candidate, context):
        if candidate.pattern_name != "DATABASE_CONNECTION_STRING":
            return None

        confidence = 0.70
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="database",
            secret_type="DATABASE_CONNECTION_STRING",
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement="<DATABASE_CONNECTION_STRING>",
            confidence=min(confidence, 1.0),
            specificity=90,
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

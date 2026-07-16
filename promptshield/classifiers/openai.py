"""
OpenAI Classifier.

Classifies OpenAI API key and Project API key candidates.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class OpenAIClassifier(BaseClassifier):

    PATTERNS = {
        "OPENAI_API_KEY": {
            "secret_type": "OPENAI_API_KEY",
            "base_confidence": 0.50,
            "base_specificity": 90,
            "replacement": "<OPENAI_API_KEY>",
        },
        "OPENAI_PROJECT_API_KEY": {
            "secret_type": "OPENAI_PROJECT_API_KEY",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<OPENAI_PROJECT_API_KEY>",
        },
    }

    CONTEXT_KEYWORDS = [
        "openai", "chatgpt", "gpt", "llm", "sk-", "ai",
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
            detector="openai",
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

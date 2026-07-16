from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class AzureClassifier(BaseClassifier):

    PATTERNS = {
        "AZURE_CLIENT_SECRET": {
            "secret_type": "AZURE_CLIENT_SECRET",
            "base_confidence": 0.50,
            "base_specificity": 70,
            "replacement": "<AZURE_CLIENT_SECRET>",
        },
        "AZURE_STORAGE_KEY": {
            "secret_type": "AZURE_STORAGE_ACCOUNT_KEY",
            "base_confidence": 0.40,
            "base_specificity": 80,
            "replacement": "<AZURE_STORAGE_ACCOUNT_KEY>",
        },
        "AZURE_SUBSCRIPTION_ID": {
            "secret_type": "AZURE_SUBSCRIPTION_ID",
            "base_confidence": 0.30,
            "base_specificity": 40,
            "replacement": "<AZURE_SUBSCRIPTION_ID>",
        },
    }

    CONTEXT_KEYWORDS = [
        "azure", "microsoft", "subscription", "tenant", "client",
        "secret", "storage_account", "DefaultEndpointsProtocol",
    ]

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        if candidate.pattern_name != "AZURE_SUBSCRIPTION_ID":
            context_text = (context.preceding + context.following + context.line).lower()
            has_context = any(kw in context_text for kw in self.CONTEXT_KEYWORDS)
            if not has_context:
                return None

        confidence = pattern_info["base_confidence"]
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="azure",
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

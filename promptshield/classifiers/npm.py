from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class NPMClassifier(BaseClassifier):

    PATTERNS = {
        "NPM_TOKEN": {
            "secret_type": "NPM_TOKEN",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<NPM_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "npm", "node", "package", ".npmrc", "registry",
    ]

    def classify(self, candidate, context):
        if candidate.pattern_name != "NPM_TOKEN":
            return None

        context_text = (context.preceding + context.following + context.line).lower()
        has_context = any(kw in context_text for kw in self.CONTEXT_KEYWORDS)
        if not has_context:
            return None

        confidence = 0.60
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="npm",
            secret_type="NPM_TOKEN",
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement="<NPM_TOKEN>",
            confidence=min(confidence, 1.0),
            specificity=100,
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

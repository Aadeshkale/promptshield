from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class SSHClassifier(BaseClassifier):

    PATTERNS = {
        "SSH_PRIVATE_KEY": {
            "secret_type": "SSH_PRIVATE_KEY",
            "base_confidence": 0.80,
            "base_specificity": 100,
            "replacement": "<SSH_PRIVATE_KEY>",
        },
    }

    CONTEXT_KEYWORDS = [
        "ssh", "private key", "rsa", "dsa", "ec", "openssh",
        "-----BEGIN", "deploy", "id_rsa",
    ]

    def classify(self, candidate, context):
        if candidate.pattern_name != "SSH_PRIVATE_KEY":
            return None

        confidence = 0.80
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="ssh",
            secret_type="SSH_PRIVATE_KEY",
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement="<SSH_PRIVATE_KEY>",
            confidence=min(confidence, 1.0),
            specificity=100,
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )

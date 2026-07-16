"""
Docker Classifier.

Classifies Docker PAT and Hub token candidates.
Hub tokens require context keywords (UUID format is ambiguous).
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class DockerClassifier(BaseClassifier):

    PATTERNS = {
        "DOCKER_PAT": {
            "secret_type": "DOCKER_PERSONAL_ACCESS_TOKEN",
            "base_confidence": 0.60,
            "base_specificity": 100,
            "replacement": "<DOCKER_PAT>",
        },
        "DOCKER_HUB_TOKEN": {
            "secret_type": "DOCKER_HUB_TOKEN",
            "base_confidence": 0.30,
            "base_specificity": 50,
            "replacement": "<DOCKER_HUB_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "docker", "dckr_pat", "container", "registry", "docker_hub",
    ]

    def classify(self, candidate, context):
        pattern_info = None
        for pattern_name, info in self.PATTERNS.items():
            if candidate.pattern_name == pattern_name:
                pattern_info = info
                break

        if not pattern_info:
            return None

        if candidate.pattern_name == "DOCKER_HUB_TOKEN":
            context_text = (context.preceding + context.following + context.line).lower()
            if not any(kw in context_text for kw in self.CONTEXT_KEYWORDS):
                return None

        confidence = pattern_info["base_confidence"]
        confidence += self._context_boost(context, self.CONTEXT_KEYWORDS)
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="docker",
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

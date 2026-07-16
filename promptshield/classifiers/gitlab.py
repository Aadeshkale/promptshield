"""
GitLab Classifier.

Classifies GitLab personal token, runner token, and OAuth token candidates.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class GitLabClassifier(BaseClassifier):

    PATTERNS = {
        "GLPAT": {
            "secret_type": "GITLAB_TOKEN",
            "base_confidence": 0.50,
            "base_specificity": 95,
            "replacement": "<GITLAB_TOKEN>",
        },
        "GLRT": {
            "secret_type": "GITLAB_RUNNER_TOKEN",
            "base_confidence": 0.50,
            "base_specificity": 95,
            "replacement": "<GITLAB_RUNNER_TOKEN>",
        },
        "GLOAS": {
            "secret_type": "GITLAB_OAUTH_ACCESS_TOKEN",
            "base_confidence": 0.50,
            "base_specificity": 95,
            "replacement": "<GITLAB_OAUTH_ACCESS_TOKEN>",
        },
    }

    CONTEXT_KEYWORDS = [
        "gitlab", "git", "gl", "personal access", "token",
        "runner", "ci/cd", "ci_cd",
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
            detector="gitlab",
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

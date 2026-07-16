"""
Bitbucket Classifier.

Classifies Bitbucket-related candidates based on pattern + context.
"""

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding


class BitbucketClassifier(BaseClassifier):

    PATTERNS = {
        "BITBUCKET_APP_PASSWORD": {
            "secret_type": "BITBUCKET_APP_PASSWORD",
            "base_confidence": 0.50,
            "base_specificity": 90,
            "replacement": "<BITBUCKET_APP_PASSWORD>",
        },
        "BITBUCKET_OAUTH_KEY": {
            "secret_type": "BITBUCKET_OAUTH_CONSUMER_KEY",
            "base_confidence": 0.30,
            "base_specificity": 60,
            "replacement": "<BITBUCKET_OAUTH_CONSUMER_KEY>",
        },
    }

    CONTEXT_KEYWORDS = [
        "bitbucket", "bb", "atlassian", "app password",
        "consumer key", "oauth",
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
            detector="bitbucket",
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

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class StripeSecretKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"
    )
    PATTERN_NAME = "STRIPE_SECRET_KEY"

    def detect(self, text):
        return [
            Candidate(
                value=match.group(),
                start=match.start(),
                end=match.end(),
                pattern_name=self.PATTERN_NAME,
            )
            for match in self.PATTERN.finditer(text)
        ]


class StripePublishableKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b"
    )
    PATTERN_NAME = "STRIPE_PUBLISHABLE_KEY"

    def detect(self, text):
        return [
            Candidate(
                value=match.group(),
                start=match.start(),
                end=match.end(),
                pattern_name=self.PATTERN_NAME,
            )
            for match in self.PATTERN.finditer(text)
        ]


class StripeWebhookSecretDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bwhsec_[A-Za-z0-9]{16,}\b"
    )
    PATTERN_NAME = "STRIPE_WEBHOOK_SECRET"

    def detect(self, text):
        return [
            Candidate(
                value=match.group(),
                start=match.start(),
                end=match.end(),
                pattern_name=self.PATTERN_NAME,
            )
            for match in self.PATTERN.finditer(text)
        ]

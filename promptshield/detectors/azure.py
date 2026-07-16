"""
Azure Pattern Detectors.

Stage 1: Pure regex matchers for Azure client secrets, storage keys,
and subscription IDs.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class AzureClientSecretDetector(BaseDetector):

    PATTERN = re.compile(
        r"[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:',.<>?/~`]{34}"
    )
    PATTERN_NAME = "AZURE_CLIENT_SECRET"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value):
                continue
            if value.lower() == value and value.isalpha():
                continue
            if not any(c in value for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                continue
            if not any(c in value for c in "!@#$%^&*()_+=-[]{}|;:,.<>?/~`"):
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class AzureStorageAccountKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"[A-Za-z0-9+/]{80,86}(?:==|=)"
    )
    PATTERN_NAME = "AZURE_STORAGE_KEY"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value):
                continue
            if value.lower() == value and value.isalpha():
                continue
            if all(c.isdigit() for c in value):
                continue
            if "=" not in value:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class AzureSubscriptionIdDetector(BaseDetector):

    PATTERN = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )
    PATTERN_NAME = "AZURE_SUBSCRIPTION_ID"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value.replace("-", "")):
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates

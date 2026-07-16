"""
Cloudflare Pattern Detectors.

Stage 1: Pure regex matchers for Cloudflare API keys and API tokens.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class CloudflareGlobalAPIKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[A-Za-z0-9]{37}\b"
    )
    PATTERN_NAME = "CLOUDFLARE_GLOBAL_API_KEY"

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
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class CloudflareAPITokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[A-Za-z0-9_-]{40}\b"
    )
    PATTERN_NAME = "CLOUDFLARE_API_TOKEN"

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
            if "_" not in value and "-" not in value:
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

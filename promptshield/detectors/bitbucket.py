"""
Bitbucket Pattern Detectors.

Stage 1: Pure regex matchers for Bitbucket app passwords and OAuth keys.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class BitbucketAppPasswordDetector(BaseDetector):

    PATTERN = re.compile(
        r"[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}"
    )
    PATTERN_NAME = "BITBUCKET_APP_PASSWORD"

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


class BitbucketOAuthConsumerKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[A-Za-z0-9]{32}\b"
    )
    PATTERN_NAME = "BITBUCKET_OAUTH_KEY"
    PEM_MARKERS = {"MII", "MIID", "MIIE", "MIIF", "MIIG", "MIH", "MIII",
                   "AAAA", "AAAAB", "AAAAC", "AAAAD"}

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value):
                continue
            if value.lower() == value and value.isalpha():
                continue
            if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in value):
                continue
            if value[:4] in self.PEM_MARKERS or value[:5] in self.PEM_MARKERS:
                continue
            if all(c in "0123456789abcdef" for c in value.lower()):
                continue
            lower_count = sum(1 for c in value if c.islower())
            if lower_count > 20:
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

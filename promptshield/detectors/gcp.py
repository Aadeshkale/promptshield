"""
GCP Pattern Detectors.

Stage 1: Pure regex matchers.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class GCPAPIKeyDetector(BaseDetector):

    PATTERN = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    PATTERN_NAME = "AIza"

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


class GCPOAuthSecretDetector(BaseDetector):

    PATTERN = re.compile(r"GOCSPX-[0-9A-Za-z\-_]{28}")
    PATTERN_NAME = "GOCSPX"

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


class GCPServiceAccountKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"-----BEGIN PRIVATE KEY-----[A-Za-z0-9/+=\s]{20,}-----END PRIVATE KEY-----"
    )
    PATTERN_NAME = "PRIVATE_KEY"

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


class GCPOAuthAccessTokenDetector(BaseDetector):

    PATTERN = re.compile(r"ya29\.[0-9A-Za-z\-_]{40,}")
    PATTERN_NAME = "ya29"

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


class GCPRefreshTokenDetector(BaseDetector):

    PATTERN = re.compile(r"1//[0-9A-Za-z\-_]{40,}")
    PATTERN_NAME = "1//"

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

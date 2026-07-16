"""
Token Pattern Detectors.

Stage 1: Pure regex matchers.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class JWTTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )
    PATTERN_NAME = "eyJ"

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


class BearerTokenDetector(BaseDetector):

    PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}")
    PATTERN_NAME = "Bearer"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            token = match.group()
            value = token.split(" ", 1)[1]
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start() + len("Bearer "),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class OAuthTokenDetector(BaseDetector):

    PATTERN = re.compile(r"OAuth\s+[A-Za-z0-9_\-\.]{20,}")
    PATTERN_NAME = "OAuth"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            token = match.group()
            value = token.split(" ", 1)[1]
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start() + len("OAuth "),
                    end=match.end(),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates

"""
AWS Pattern Detectors.

Stage 1: Pure regex matchers.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class AWSAccessKeyDetector(BaseDetector):

    PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
    PATTERN_NAME = "AKIA"

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


class AWSTemporaryKeyDetector(BaseDetector):

    PATTERN = re.compile(r"ASIA[0-9A-Z]{16}")
    PATTERN_NAME = "ASIA"

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


class AWSSecretKeyDetector(BaseDetector):

    PATTERN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])")
    PATTERN_NAME = "SECRET_KEY"
    EXCLUDE_PREFIXES = ["AIza", "ya29", "GOCSPX"]
    TOKEN_PREFIXES = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "glrt-", "gloas-", "dckr_pat_"]

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c in "=/+" for c in value):
                continue
            if any(value.startswith(prefix) for prefix in self.EXCLUDE_PREFIXES):
                continue
            start = match.start()
            for prefix in self.TOKEN_PREFIXES:
                if start >= len(prefix) and text[start - len(prefix):start] == prefix:
                    break
            else:
                candidates.append(
                    Candidate(
                        value=value,
                        start=start,
                        end=match.end(),
                        pattern_name=self.PATTERN_NAME,
                    )
                )
        return candidates


class AWSSessionTokenDetector(BaseDetector):

    PATTERN = re.compile(r"(?:FwoG|IQoJ)[A-Za-z0-9/+=]{80,}")
    PATTERN_NAME = "SESSION_TOKEN"

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

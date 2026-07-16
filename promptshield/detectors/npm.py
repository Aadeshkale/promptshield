"""
NPM Pattern Detector.

Stage 1: Pure regex matcher for NPM access tokens (npm_ prefix).
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class NPMAccessTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bnpm_[A-Za-z0-9]{36,}\b"
    )
    PATTERN_NAME = "NPM_TOKEN"

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

"""
Heroku Pattern Detector.

Stage 1: Pure regex matcher for Heroku API keys (UUID format).
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class HerokuAPIKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b"
    )
    PATTERN_NAME = "HEROKU_API_KEY"

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

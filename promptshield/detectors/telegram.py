"""
Telegram Pattern Detector.

Stage 1: Pure regex matcher for Telegram bot tokens.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class TelegramBotTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35,}\b"
    )
    PATTERN_NAME = "TELEGRAM_BOT_TOKEN"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if ":" not in value:
                continue
            left, right = value.split(":", 1)
            if not left.isdigit():
                continue
            if len(left) < 8 or len(right) < 30:
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

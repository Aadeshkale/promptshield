"""
Slack Pattern Detectors.

Stage 1: Pure regex matchers for Slack bot tokens, user tokens,
and webhook URLs.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class SlackBotTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bxoxb-[0-9A-Za-z\-]{10,}\b"
    )
    PATTERN_NAME = "SLACK_BOT_TOKEN"

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


class SlackUserTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bxoxp-[0-9A-Za-z\-]{10,}\b"
    )
    PATTERN_NAME = "SLACK_USER_TOKEN"

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


class SlackWebhookDetector(BaseDetector):

    PATTERN = re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
    )
    PATTERN_NAME = "SLACK_WEBHOOK"

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

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class TwilioAccountSIDDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bAC[A-Za-z0-9]{32}\b"
    )
    PATTERN_NAME = "TWILIO_ACCOUNT_SID"

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


class TwilioAuthTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bSK[A-Za-z0-9]{32}\b"
    )
    PATTERN_NAME = "TWILIO_AUTH_TOKEN"

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

"""
AWS Access Key detector.

Currently detects only:
  AKIAxxxxxxxxxxxxxxxx

Later we can add:
  AWS Secret Key
  Session Token
  IAM Role ARN
  etc.
"""

import re

from promptshield.models import Finding
from promptshield.detectors.base import BaseDetector


class AWSAccessKeyDetector(BaseDetector):

    NAME = "aws"
    PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="AWS_ACCESS_KEY",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<AWS_ACCESS_KEY>",
                )
            )

        return findings

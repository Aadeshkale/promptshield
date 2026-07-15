"""
AWS secret detectors.

Detects:
  AWS Access Key        AKIAxxxxxxxxxxxxxxxx
  AWS Temporary Key     ASIAxxxxxxxxxxxxxxxx
  AWS Secret Key        40-char base64 string
  AWS Session Token     FwoG... long base64 blob
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


class AWSTemporaryKeyDetector(BaseDetector):

    NAME = "aws"
    PATTERN = re.compile(r"ASIA[0-9A-Z]{16}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="AWS_TEMPORARY_KEY",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<AWS_TEMPORARY_KEY>",
                )
            )

        return findings


class AWSSecretKeyDetector(BaseDetector):

    NAME = "aws"
    PATTERN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c in "=/+" for c in value):
                continue
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="AWS_SECRET_KEY",
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    replacement="<AWS_SECRET_KEY>",
                )
            )

        return findings


class AWSSessionTokenDetector(BaseDetector):

    NAME = "aws"
    PATTERN = re.compile(r"(?:FwoG|IQoJ)[A-Za-z0-9/+=]{80,}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="AWS_SESSION_TOKEN",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<AWS_SESSION_TOKEN>",
                )
            )

        return findings

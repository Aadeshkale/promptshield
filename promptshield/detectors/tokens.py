"""
OAuth / JWT secret detectors.

Detects:
  JWT Token            eyJhbGci... (three-part base64url)
  Bearer Token         Bearer <token>
  Generic OAuth Token  OAuth <token>
"""

import re

from promptshield.models import Finding
from promptshield.detectors.base import BaseDetector


class JWTTokenDetector(BaseDetector):

    NAME = "oauth"
    PATTERN = re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="JWT_TOKEN",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<JWT_TOKEN>",
                )
            )

        return findings


class BearerTokenDetector(BaseDetector):

    NAME = "oauth"
    PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            token = match.group()
            value = token.split(" ", 1)[1]
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="BEARER_TOKEN",
                    value=value,
                    start=match.start() + len("Bearer "),
                    end=match.end(),
                    replacement="<BEARER_TOKEN>",
                )
            )

        return findings


class OAuthTokenDetector(BaseDetector):

    NAME = "oauth"
    PATTERN = re.compile(r"OAuth\s+[A-Za-z0-9_\-\.]{20,}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            token = match.group()
            value = token.split(" ", 1)[1]
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="OAUTH_TOKEN",
                    value=value,
                    start=match.start() + len("OAuth "),
                    end=match.end(),
                    replacement="<OAUTH_TOKEN>",
                )
            )

        return findings

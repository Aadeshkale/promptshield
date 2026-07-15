"""
GCP secret detectors.

Detects:
  GCP API Key           AIzaSy...
  GCP OAuth Secret      GOCSPX-...
  GCP SA Key (PEM)      -----BEGIN PRIVATE KEY-----
  GCP OAuth Token       ya29....
  GCP Refresh Token     1//...
"""

import re

from promptshield.models import Finding
from promptshield.detectors.base import BaseDetector


class GCPAPIKeyDetector(BaseDetector):

    NAME = "gcp"
    PATTERN = re.compile(r"AIza[0-9A-Za-z\-_]{35}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="GCP_API_KEY",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<GCP_API_KEY>",
                )
            )

        return findings


class GCPOAuthSecretDetector(BaseDetector):

    NAME = "gcp"
    PATTERN = re.compile(r"GOCSPX-[0-9A-Za-z\-_]{28}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="GCP_OAUTH_SECRET",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<GCP_OAUTH_SECRET>",
                )
            )

        return findings


class GCPServiceAccountKeyDetector(BaseDetector):

    NAME = "gcp"
    PATTERN = re.compile(
        r"-----BEGIN PRIVATE KEY-----[A-Za-z0-9/+=\s]{20,}-----END PRIVATE KEY-----"
    )

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="GCP_SA_KEY",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<GCP_SA_KEY>",
                )
            )

        return findings


class GCPOAuthAccessTokenDetector(BaseDetector):

    NAME = "gcp"
    PATTERN = re.compile(r"ya29\.[0-9A-Za-z\-_]{40,}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="GCP_OAUTH_TOKEN",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<GCP_OAUTH_TOKEN>",
                )
            )

        return findings


class GCPRefreshTokenDetector(BaseDetector):

    NAME = "gcp"
    PATTERN = re.compile(r"1//[0-9A-Za-z\-_]{40,}")

    def detect(self, text):
        findings = []

        for match in self.PATTERN.finditer(text):
            findings.append(
                Finding(
                    detector=self.NAME,
                    secret_type="GCP_REFRESH_TOKEN",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    replacement="<GCP_REFRESH_TOKEN>",
                )
            )

        return findings

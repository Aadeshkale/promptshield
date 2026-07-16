import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class GitHubTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b(?:gh[opurs])_[A-Za-z0-9_]{36,40}\b"
    )
    PATTERN_NAME = "GITHUB_TOKEN"

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


class GitHubSSHKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b(?:ssh-rsa|ssh-ed25519|ssh-dss)\s+AAAAB[A-Za-z0-9+/=]{50,}\b"
    )
    PATTERN_NAME = "GITHUB_SSH_KEY"

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

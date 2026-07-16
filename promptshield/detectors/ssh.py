"""
SSH Private Key Pattern Detector.

Stage 1: Pure regex matcher for PEM-format private keys (RSA, DSA, EC, OpenSSH).
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class SSHPrivateKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----[\sA-Za-z0-9+/=]{20,}-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"
    )
    PATTERN_NAME = "SSH_PRIVATE_KEY"

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

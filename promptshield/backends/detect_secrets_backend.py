"""
Backend wrapper for Yelp's detect-secrets scanner.

Requires: pip install promptshield[backends]
"""

import logging
from typing import List

from promptshield.backends.base import BackendScanner
from promptshield.models import Finding

log = logging.getLogger(__name__)


class DetectSecretsBackend(BackendScanner):
    """Scan text using detect-secrets' Python API."""

    def __init__(self, confidence: float = 0.70, specificity: int = 80):
        self.confidence = confidence
        self.specificity = specificity

    def scan(self, text: str) -> List[Finding]:
        try:
            from detect_secrets.core.scan import scan_line
            from detect_secrets.settings import default_settings
        except ImportError:
            log.warning(
                "detect-secrets is not installed. "
                "Install it with: pip install promptshield[backends]"
            )
            return []

        findings: List[Finding] = []
        with default_settings():
            for line in text.splitlines(keepends=True):
                for secret in scan_line(line):
                    value = secret.secret_value
                    if not value:
                        continue
                    line_text = line.rstrip("\n\r")
                    start = text.find(value)
                    if start == -1:
                        start = 0
                    findings.append(Finding(
                        detector="detect-secrets",
                        secret_type=secret.type,
                        value=value,
                        start=start,
                        end=start + len(value),
                        replacement=f"<{secret.type}>",
                        confidence=self.confidence,
                        specificity=self.specificity,
                        line=secret.line_number or 0,
                        verified=secret.is_verified,
                    ))
        return findings

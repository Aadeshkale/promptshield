"""
Observability Service Pattern Detectors.

Stage 1: Pure regex matchers for Datadog API/App keys, New Relic
API keys, and Sentry DSNs.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class DatadogAPIKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[A-Za-z0-9]{32}\b"
    )
    PATTERN_NAME = "DATADOG_API_KEY"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value):
                continue
            if value.lower() == value and value.isalpha():
                continue
            if all(c.isdigit() for c in value):
                continue
            if not any(c.isdigit() for c in value):
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


class DatadogAppKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[A-Za-z0-9]{40}\b"
    )
    PATTERN_NAME = "DATADOG_APP_KEY"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value):
                continue
            if value.lower() == value and value.isalpha():
                continue
            if all(c.isdigit() for c in value):
                continue
            if not any(c.isdigit() for c in value):
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


class NewRelicAPIKeyDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bNRAK-[A-Za-z0-9_-]{27,}\b"
    )
    PATTERN_NAME = "NEW_RELIC_API_KEY"

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


class SentryDSNDetector(BaseDetector):

    PATTERN = re.compile(
        r"https://[a-f0-9]{32}@[A-Za-z0-9.-]+\.ingest\.sentry\.io/\d+"
    )
    PATTERN_NAME = "SENTRY_DSN"

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

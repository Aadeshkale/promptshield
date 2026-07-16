import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class GitLabTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"glpat-[A-Za-z0-9\-_]{20,}"
    )
    PATTERN_NAME = "GLPAT"

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


class GitLabRunnerTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"glrt-[A-Za-z0-9\-_]{20,}"
    )
    PATTERN_NAME = "GLRT"

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


class GitLabOTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"gloas-[A-Za-z0-9\-_]{40,}"
    )
    PATTERN_NAME = "GLOAS"

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

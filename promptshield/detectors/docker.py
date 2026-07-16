import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class DockerPATDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"
    )
    PATTERN_NAME = "DOCKER_PAT"

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


class DockerHubTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b"
    )
    PATTERN_NAME = "DOCKER_HUB_TOKEN"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if all(c == value[0] for c in value.replace("-", "")):
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

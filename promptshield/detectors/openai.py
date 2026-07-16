import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class OpenAIAPIDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bsk-[A-Za-z0-9]{20,}\b"
    )
    PATTERN_NAME = "OPENAI_API_KEY"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if not value.startswith("sk-"):
                continue
            if value.startswith("sk_live") or value.startswith("sk_test"):
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


class OpenAIProjectAPIDetector(BaseDetector):

    PATTERN = re.compile(
        r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"
    )
    PATTERN_NAME = "OPENAI_PROJECT_API_KEY"

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

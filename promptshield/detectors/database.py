import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class DatabaseConnectionStringDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[^\s:/]+:[^\s@]+@[^\s]{3,}\b"
    )
    PATTERN_NAME = "DATABASE_CONNECTION_STRING"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if "example" in value.lower() or "localhost" in value.lower():
                continue
            parts = value.split("://", 1)
            if len(parts) < 2:
                continue
            after_scheme = parts[1]
            if "@" not in after_scheme:
                continue
            auth_part = after_scheme.split("@")[0]
            if ":" not in auth_part:
                continue
            user, password = auth_part.split(":", 1)
            if not password or not user:
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

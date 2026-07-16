import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class DiscordBotTokenDetector(BaseDetector):

    PATTERN = re.compile(
        r"\b[NM][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\b"
    )
    PATTERN_NAME = "DISCORD_BOT_TOKEN"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if "." not in value or ":" in value:
                continue
            parts = value.split(".")
            if len(parts) != 2:
                continue
            if len(parts[1]) != 6:
                continue
            if match.start() > 0 and text[match.start() - 1].isalnum():
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

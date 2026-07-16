import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


class PasswordAssignmentDetector(BaseDetector):

    PATTERN = re.compile(
        r"""(?ix)
        (?:                                        # key name
            (?:password|passwd|pwd|passphrase|secret|pass)
            \s*[:=]\s*
            (?:
                ["']?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:',.<>?/~`]{4,})["']?
                |
                `([A-Za-z0-9_]+)`                 # backtick env var
            )
        )
        """
    )
    PATTERN_NAME = "PASSWORD_ASSIGNMENT"
    EXCLUDED_VALUES = {"password", "passwd", "password123", "changeme",
                       "name", "user", "username", "example", "test"}

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = (match.group(1) or match.group(2) or "").strip()
            value = value.strip("\"'")
            lower = value.lower()
            if lower in self.EXCLUDED_VALUES:
                continue
            if all(c == value[0] for c in value):
                continue
            if value.isdigit() and int(value) < 1900:
                continue
            if value.lower() in ("true", "false", "yes", "no", "none", "null"):
                continue
            start = match.start(1) or match.start(2)
            end = match.end(1) or match.end(2)
            candidates.append(
                Candidate(
                    value=value,
                    start=start,
                    end=end,
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class UsernameAssignmentDetector(BaseDetector):

    PATTERN = re.compile(
        r"""(?ix)
        (?:
            (?:username|user_name|user|login)
            \s*[:=]\s*
            ["']?([A-Za-z0-9_.@-]{3,})["']?
        )
        """
    )
    PATTERN_NAME = "USERNAME_ASSIGNMENT"
    EXCLUDED_VALUES = {"user", "username", "admin", "root", "guest",
                       "test", "name", "login", "example"}

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group(1).strip().strip("\"'")
            lower = value.lower()
            if lower in self.EXCLUDED_VALUES:
                continue
            if all(c == value[0] for c in value):
                continue
            if "@" in value and "." in value.split("@")[1]:
                continue
            candidates.append(
                Candidate(
                    value=value,
                    start=match.start(1),
                    end=match.end(1),
                    pattern_name=self.PATTERN_NAME,
                )
            )
        return candidates


class BasicAuthURLDetector(BaseDetector):

    PATTERN = re.compile(
        r"https?://[A-Za-z0-9_.%-]+:[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:',.<>?/~`%]+@[A-Za-z0-9.-]+"
    )
    PATTERN_NAME = "BASIC_AUTH_URL"

    def detect(self, text):
        candidates = []
        for match in self.PATTERN.finditer(text):
            value = match.group()
            if "example" in value.lower():
                continue
            auth_part = value.split("://", 1)[1].split("@", 1)[0]
            if ":" not in auth_part:
                continue
            user, password = auth_part.split(":", 1)
            if len(password) < 3 or len(user) < 1:
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


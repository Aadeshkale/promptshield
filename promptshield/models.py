from dataclasses import dataclass, field
from typing import List


@dataclass
class Candidate:
    """Stage 1: Raw regex match from detector."""

    value: str
    start: int
    end: int
    pattern_name: str  # e.g., "AKIA", "ya29", "eyJ"


@dataclass
class Context:
    """Stage 2: Surrounding information for a candidate."""

    preceding: str        # previous 30 chars
    following: str        # next 30 chars
    line: str             # full line text
    line_number: int
    preceding_line: str   # previous line
    env_var: str          # e.g., "AWS_ACCESS_KEY_ID"
    header: str           # e.g., "Authorization: Bearer"


@dataclass
class Finding:
    """Stage 3: Classified secret with metadata."""

    detector: str
    secret_type: str
    value: str
    start: int
    end: int
    replacement: str
    confidence: float = 1.0
    specificity: int = 100
    context_before: str = ""
    context_after: str = ""
    line: int = 0
    column: int = 0
    verified: bool = False


@dataclass
class ScanResult:
    """Final result returned by PromptShield."""

    original_text: str
    redacted_text: str
    findings: List[Finding]

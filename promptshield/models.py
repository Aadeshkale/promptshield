from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    """
    Information about one detected secret.
    """

    detector: str          # Detector name (aws, github, etc.)
    secret_type: str       # Type of secret
    value: str             # Secret that was found
    start: int             # Start position in text
    end: int               # End position in text
    replacement: str       # Replacement text


@dataclass
class ScanResult:
    """
    Final result returned by PromptShield.
    """

    original_text: str
    redacted_text: str
    findings: List[Finding]

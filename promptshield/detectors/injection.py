"""
Prompt Injection Pattern Detectors.

Stage 1: Pure regex matchers for known injection patterns.
Return Candidate objects for classification in later stages.
"""

import re

from promptshield.detectors.base import BaseDetector
from promptshield.models import Candidate


INJECTION_PATTERNS = {
    "instruction_override": re.compile(
        r"(?:ignore|disregard|forget|override|bypass|skip|drop|throw\s+away|discard)"
        r"(?:\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding|your|the))"
        r"(?:\s+(?:instructions?|prompts?|rules?|guidelines?|constraints?|restrictions?|directives?))",
        re.IGNORECASE,
    ),
    "role_hijack": re.compile(
        r"(?:you\s+are\s+now|act\s+as\s+(?:if\s+)?(?:you\s+are\s+)?|pretend\s+(?:you\s+are|to\s+be)|"
        r"enter\s+(?:developer|debug|admin|god|DAN|unrestricted|jailbreak)\s+mode|"
        r"(?:DAN|Do\s+Anything\s+Now|STAN|Keplun|DUDE|AIM)\s*(?:mode|:))",
        re.IGNORECASE,
    ),
    "system_extraction": re.compile(
        r"(?:reveal|show|display|output|print|repeat|share|tell\s+me|what\s+(?:were|are)|"
        r"repeat\s+(?:the|everything)\s+(?:text|above|in\s+your|starting\s+with)|"
        r"copy\s+(?:the|your)\s+(?:above|previous|system)|"
        r"what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?))\s*"
        r"(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|initial\s+message)?",
        re.IGNORECASE,
    ),
    "delimiter_injection": re.compile(
        r"(?:</?(?:system|user|assistant|instructions?|context|prompt|规则|指令)>|"
        r"\[(?:system|INST|/INST)\]|"
        r"<<SYS>>|<</SYS>>|"
        r"---\s*(?:BEGIN|END)\s*(?:SYSTEM|INSTRUCTION|OVERRIDE)|"
        r"###\s*(?:SYSTEM|INSTRUCTION|OVERRIDE))",
        re.IGNORECASE,
    ),
    "new_instructions": re.compile(
        r"(?:new|updated|revised|actual|real|true)\s+(?:instructions?|prompt|rules?|directive)s?\s*:",
        re.IGNORECASE,
    ),
    "developer_mode": re.compile(
        r"(?:developer|debug|admin|god|unrestricted|unfiltered|uncensored|evil)\s+mode",
        re.IGNORECASE,
    ),
    "encoded_payload": re.compile(
        r"^(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9a-fA-F]{40,})$",
    ),
    "data_exfil": re.compile(
        r"<img\s+src\s*=\s*[\"']https?://[^\"']*\?(?:[^\"']*=)",
        re.IGNORECASE,
    ),
}


class InjectionPatternDetector(BaseDetector):
    """
    Detects prompt injection patterns using regex.

    Each match returns a Candidate with pattern_name indicating
    the injection category.
    """

    def detect(self, text):
        candidates = []
        for category, pattern in INJECTION_PATTERNS.items():
            for match in pattern.finditer(text):
                candidates.append(
                    Candidate(
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        pattern_name=f"INJECTION_{category.upper()}",
                    )
                )
        return candidates

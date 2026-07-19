"""
Backend wrapper for prompt-injection-defense library.

Lightweight, rule-based prompt injection detector aligned with
OWASP Top 10:2025. Detects jailbreaks, obfuscation, and unsafe content.

Requires: pip install promptshield[backends]
"""

import logging
from typing import List

from promptshield.backends.injection_base import InjectionBackend
from promptshield.models import InjectionResult

log = logging.getLogger(__name__)


class PromptInjectionDefenseBackend(InjectionBackend):
    """Scan text using prompt-injection-defense's rule-based detection."""

    def __init__(
        self,
        threshold_suspicious: int = 2,
        threshold_high_risk: int = 5,
        action: str = "flag",
    ):
        self.threshold_suspicious = threshold_suspicious
        self.threshold_high_risk = threshold_high_risk
        self.action = action

    def scan(self, text: str) -> InjectionResult:
        try:
            from prompt_injection_defense import detect_prompt_injection
        except ImportError:
            log.warning(
                "prompt-injection-defense is not installed. "
                "Install it with: pip install promptshield[backends]"
            )
            return InjectionResult(
                threat_score=0.0,
                blocked=False,
                scores={},
                patterns_matched=[],
                action=self.action,
            )

        result = detect_prompt_injection(
            text,
            threshold_suspicious=self.threshold_suspicious,
            threshold_high_risk=self.threshold_high_risk,
        )

        score = result.get("score", 0)
        label = result.get("label", "benign")
        categories = result.get("owasp_categories", [])
        reasons = result.get("reasons", [])

        normalized_score = min(score / 10.0, 1.0)
        blocked = label == "high_risk"

        patterns: List[str] = []
        for cat in categories:
            if cat not in patterns:
                patterns.append(cat)
        for reason in reasons:
            tag = reason.split("]")[0].lstrip("[") if "]" in reason else reason[:30]
            if tag not in patterns:
                patterns.append(tag)

        return InjectionResult(
            threat_score=round(normalized_score, 4),
            blocked=blocked,
            scores={"prompt_injection_defense": round(normalized_score, 4)},
            patterns_matched=patterns,
            action=self.action,
        )

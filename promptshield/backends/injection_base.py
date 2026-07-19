"""
Base class for third-party prompt injection protection backends.

Each backend wraps an external injection detection library and converts
its output to PromptShield's InjectionResult format.
"""

from abc import ABC, abstractmethod

from promptshield.models import InjectionResult


class InjectionBackend(ABC):

    @abstractmethod
    def scan(self, text: str) -> InjectionResult:
        """
        Scan text for prompt injection attacks.

        Returns an InjectionResult with threat_score, blocked status,
        and patterns matched. If the backend dependency is not installed,
        return a safe default (threat_score=0.0, blocked=False).
        """
        pass

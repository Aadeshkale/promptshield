"""
Custom exceptions for PromptShield.
"""


class PromptShieldError(Exception):
    """Base exception for all PromptShield errors."""


class InjectionDetected(PromptShieldError):
    """Raised when prompt injection is detected in block mode."""

    def __init__(self, threat_score: float, patterns_matched: list):
        self.threat_score = threat_score
        self.patterns_matched = patterns_matched
        super().__init__(
            f"Prompt injection detected (threat: {threat_score:.2f}, "
            f"patterns: {', '.join(patterns_matched)})"
        )


class InvalidConfigurationError(PromptShieldError):
    """Raised when PromptShield is initialized with invalid parameters."""


class ScanError(PromptShieldError):
    """Raised when a scan operation fails."""

    def __init__(self, message: str, *, backend: str | None = None, cause: Exception | None = None):
        self.backend = backend
        self.cause = cause
        detail = f" (backend: {backend})" if backend else ""
        super().__init__(f"{message}{detail}")
        if cause:
            self.__cause__ = cause

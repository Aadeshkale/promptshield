"""
Custom exceptions for PromptShield.
"""


class InjectionDetected(Exception):
    """Raised when prompt injection is detected in block mode."""

    def __init__(self, threat_score: float, patterns_matched: list):
        self.threat_score = threat_score
        self.patterns_matched = patterns_matched
        super().__init__(
            f"Prompt injection detected (threat: {threat_score:.2f}, "
            f"patterns: {', '.join(patterns_matched)})"
        )

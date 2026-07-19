"""
Third-party scanner backends for secret detection, PII detection,
and prompt injection protection.

This module provides optional integrations with external tools.
Each backend wraps a third-party library and converts its output
to PromptShield's data formats.

Requires: pip install promptshield[backends]
"""

from promptshield.backends.base import BackendScanner
from promptshield.backends.detect_secrets_backend import DetectSecretsBackend
from promptshield.backends.injection_base import InjectionBackend
from promptshield.backends.presidio_pii_backend import PresidioPIIBackend
from promptshield.backends.prompt_injection_defense_backend import PromptInjectionDefenseBackend

__all__ = [
    "BackendScanner",
    "DetectSecretsBackend",
    "InjectionBackend",
    "PresidioPIIBackend",
    "PromptInjectionDefenseBackend",
]

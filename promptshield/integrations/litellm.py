"""
LiteLLM integration for PromptShield.

Usage in litellm_config.yaml:

    litellm_settings:
      callbacks: promptshield.integrations.litellm.PromptShieldGuard

    # optional overrides:
    #   callback_args:
    #     PromptShieldGuard:
    #       injection_mode: redact
    #       injection_threshold: 0.85

Requires: pip install promptshield[litellm]
"""

from promptshield import PromptShield
from promptshield.exceptions import InjectionDetected

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:
    CustomLogger = object


class PromptShieldGuard(CustomLogger):
    """
    LiteLLM callback that scans every request with PromptShield.

    - Detects and redacts secrets (API keys, tokens, credentials).
    - Detects prompt injection attempts and blocks flagged requests.
    - Passes through clean requests unchanged.
    """

    def __init__(
        self,
        use_injection: bool = True,
        injection_mode: str = "block",
        injection_threshold: float = 0.7,
        detectors: list | None = None,
        backends: list | None = None,
        injection_backends: list | None = None,
    ):
        self.shield = PromptShield(
            detectors=detectors,
            backends=backends,
            injection_backends=injection_backends,
            use_injection=use_injection,
            injection_threshold=injection_threshold,
            injection_mode=injection_mode,
        )

    async def async_pre_call_hook(
        self, user_api_key_dict, cache, call_type, request_body
    ):
        messages = request_body.get("messages", [])
        if not messages:
            return request_body

        modified = list(messages)
        has_changes = False

        for i, msg in enumerate(modified):
            content = msg.get("content")
            if not isinstance(content, str):
                continue

            try:
                result = self.shield.scan(content)
            except InjectionDetected as e:
                raise ValueError(
                    f"Prompt injection detected "
                    f"(threat_score={e.threat_score}, "
                    f"patterns={e.patterns_matched})"
                )

            if result.injection and result.injection.blocked:
                raise ValueError(
                    f"Prompt injection detected "
                    f"(threat_score={result.injection.threat_score}, "
                    f"patterns={result.injection.patterns_matched})"
                )

            if result.redacted_text != content:
                modified[i] = {**msg, "content": result.redacted_text}
                has_changes = True

        if has_changes:
            request_body["messages"] = modified

        return request_body

"""
Framework-agnostic middleware for scanning LLM requests.

Use this to build custom proxies, middleware for any web framework,
or CLI tools that process prompts before sending them to an LLM provider.

Usage with FastAPI:

    from fastapi import FastAPI
    from promptshield.integrations.shield_middleware import ShieldMiddleware

    guard = ShieldMiddleware()
    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def chat(request: dict):
        messages, findings, injection = guard.scan_messages(request["messages"])
        if error := guard.check_blocked(injection):
            return {"error": error}, 403
        # forward redacted messages to upstream provider
        ...

Usage with any framework:

    guard = ShieldMiddleware()
    messages, findings, injection = guard.scan_messages(request_body["messages"])
    if guard.check_blocked(injection):
        # block the request
    else:
        # forward with redacted messages
"""

from promptshield import PromptShield
from promptshield.exceptions import InjectionDetected


class ShieldMiddleware:
    """
    Framework-agnostic scanner for LLM proxy requests.

    Scans message content for secrets and prompt injections,
    redacts sensitive data, and reports whether the request
    should be blocked.
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

    def scan_messages(self, messages: list[dict]) -> tuple[list[dict], list, object | None]:
        """
        Scan all message contents for secrets and injections.

        Args:
            messages: List of message dicts (e.g. [{"role": "user", "content": "..."}])

        Returns:
            (modified_messages, findings, injection_result)
            - modified_messages: messages with secrets redacted
            - findings: list of all Finding objects
            - injection_result: merged InjectionResult or None
        """
        modified = list(messages)
        all_findings = []
        injection_results = []

        for msg in modified:
            content = msg.get("content")
            if not isinstance(content, str):
                continue

            try:
                result = self.shield.scan(content)
            except InjectionDetected as e:
                all_findings.extend(result.findings if hasattr(result, "findings") else [])
                injection_results.append(
                    type("InjectionResult", (), {
                        "threat_score": e.threat_score,
                        "blocked": True,
                        "patterns_matched": e.patterns_matched,
                        "action": "block",
                    })
                )
                msg["content"] = result.redacted_text if hasattr(result, "redacted_text") else content
                continue

            all_findings.extend(result.findings)

            if result.injection:
                injection_results.append(result.injection)

            msg["content"] = result.redacted_text

        merged_injection = self._merge_injection_results(injection_results) if injection_results else None

        return modified, all_findings, merged_injection

    def check_blocked(self, injection_result: object | None) -> str | None:
        """
        Check if the scan result indicates a blocked request.

        Args:
            injection_result: The merged InjectionResult from scan_messages(), or None

        Returns:
            None if safe, or an error message string if the request should be blocked.
        """
        if injection_result is None:
            return None
        if getattr(injection_result, "blocked", False):
            return (
                f"Prompt injection detected "
                f"(threat_score={injection_result.threat_score}, "
                f"patterns={injection_result.patterns_matched})"
            )
        return None

    def _merge_injection_results(self, results: list) -> object:
        merged = type("InjectionResult", (), {
            "threat_score": 0.0,
            "blocked": False,
            "patterns_matched": [],
            "scores": {},
            "action": results[0].action if results else "block",
        })

        for r in results:
            merged.threat_score = max(merged.threat_score, r.threat_score)
            merged.blocked = merged.blocked or r.blocked
            for p in getattr(r, "patterns_matched", []):
                if p not in merged.patterns_matched:
                    merged.patterns_matched.append(p)

        merged.threat_score = round(merged.threat_score, 4)
        return merged

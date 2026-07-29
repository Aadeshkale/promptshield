"""
Proxy and framework integrations for PromptShield.

Provides ready-to-use integrations that can be dropped into
existing proxy infrastructure with minimal configuration.

Available integrations:
  - LiteLLM:  PromptShieldGuard(CustomLogger) — callback for LiteLLM proxy
  - Generic:  ShieldMiddleware — framework-agnostic scanner for custom proxies
"""

"""
Example: Using PromptShieldGuard with LiteLLM proxy.

This file shows two ways to use the integration:

1. Via config file (recommended):
   litellm --config litellm_proxy_config.yaml --port 4000

2. Programmatically via the callback class:
"""

from litellm import Router
from promptshield.integrations.litellm import PromptShieldGuard


def main():
    # Register the callback programmatically
    guard = PromptShieldGuard(
        use_injection=True,
        injection_mode="block",
        injection_threshold=0.7,
    )

    router = Router(
        model_list=[
            {
                "model_name": "gpt-4",
                "litellm_params": {
                    "model": "openai/gpt-4",
                    "api_key": "os.environ/OPENAI_API_KEY",
                },
            },
        ],
        callbacks=[guard],
    )

    # All requests through this router will be scanned
    response = router.completion(
        model="gpt-4",
        messages=[
            {"role": "user", "content": "What is the capital of France?"}
        ],
    )
    print(response["choices"][0]["message"]["content"])


if __name__ == "__main__":
    main()

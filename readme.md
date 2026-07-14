# PromptShield

**PromptShield** is an open-source prompt security library for AI applications. It inspects prompts before they reach Large Language Models (LLMs), detects secrets and sensitive information, applies configurable security policies, and returns a sanitized prompt that can be safely sent to providers such as OpenAI, Claude, Gemini, and Ollama.

```bash
               PromptShield
                     │
     ┌───────────────┼────────────────┐
     │               │                │
 Secret Scan     PII Scan     Prompt Injection
     │               │                │
     └───────────────┼────────────────┘
                     │
              Policy Engine
                     │
               Model Router
                     │
       OpenAI / Claude / Gemini / Ollama
```

## Features

- Secret Detection
- PII Detection
- Prompt Injection Protection
- Jailbreak Detection
- Malware Detection
- Response Filtering
- AI Governance
- Policy Engine
- Audit Logs
- Multi-LLM Routing

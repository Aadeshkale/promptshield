# PromptShield

**PromptShield** is an enterprise AI security gateway that sits between applications and LLM providers like OpenAI, Claude, Gemini, and Ollama. It detects and redacts secrets, protects sensitive data

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

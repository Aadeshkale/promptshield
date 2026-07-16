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

## Roadmap

PromptShield is developed in two stages:

1. **Library** (current) — Embeddable Python library that scans and sanitizes prompts before they reach any LLM.
2. **Proxy** (future) — A transparent forward proxy. All traffic to LLM providers flows through it. Secrets, PII, and prompt injections are removed automatically — no application changes required.

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

## Supported Secrets

| Provider | Types detected | Context-required |
|---|---|---|
| AWS | Access Key, Secret Key, Session Token, Temporary Key | |
| GCP | API Key, OAuth Secret, Service Account, Access/Refresh Token | yes |
| Azure | Client Secret, Storage Key, Subscription ID | mostly |
| GitHub | Personal Access Token (ghp/gpo/gpu/gps), SSH Key | |
| GitLab | Personal, Runner, OAuth Tokens | |
| Bitbucket | App Password, OAuth Consumer Key | |
| Cloudflare | API Key, API Token | yes |
| Telegram | Bot Token | |
| Discord | Bot Token | |
| Stripe | Secret/Publishable/Webhook Keys | publishable only |
| Slack | Bot/User tokens, Webhooks | |
| Generic | JWT, Bearer, OAuth tokens | |
| Twilio | Account SID, Auth Token | yes |
| Heroku | API Key | yes |
| NPM | Access Token | yes |
| OpenAI | API Key, Project API Key | |
| Docker | PAT, Hub Token | hub only |
| Datadog | API/App keys | yes |
| NewRelic | API key | |
| Sentry | DSN | |
| Hardcoded | password, username, basic auth URLs | |

## Quickstart

```python
from promptshield import PromptShield

shield = PromptShield()

result = shield.scan("snippet with API keys")
if result.findings:
    print("Redacted:", result.redacted_text)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 PromptShield Contributors. Licensed under AGPL-3.0-or-later.

"""
Slack credentials example.

Run from project root:
  python3 examples/slack_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Slack Bot Token:
xoxb-123456789012-abcdefghijklmnopqrstuvwxyz

Slack User Token:
xoxp-123456789012-abcdefghijklmnopqrstuvwxyz

Slack Webhook URL:
https://hooks.slack.com/services/T00ABCDEF/B00GHIJKL/xxxxxxxxxxxx

Config:
  slack_bot_token: xoxb-987654321098-zyxwvutsrqponmlkjihgfedcba
  slack_webhook: https://hooks.slack.com/services/T00/B00/yyyyyyyyyyyy
"""

result = shield.scan(text)

print("=" * 50)
print("Original")
print(result.original_text)
print()
print("=" * 50)
print("Redacted")
print(result.redacted_text)
print()
print("=" * 50)
print("Findings")
for finding in result.findings:
    print(f"  {finding.secret_type}")
    print(f"    detector: {finding.detector}")
    print(f"    confidence: {finding.confidence:.2f}")
    print(f"    specificity: {finding.specificity}")
    print(f"    value: {finding.value[:30]}...")
    print()

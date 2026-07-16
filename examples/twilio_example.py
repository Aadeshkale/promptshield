"""
Twilio credentials example.

Run from project root:
  python3 examples/twilio_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Twilio Account SID:
  TWILIO_ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Twilio Auth Token:
  TWILIO_AUTH_TOKEN=SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Config:
  account_sid: ACbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  auth_token: SKccccccccccccccccccccccccccccccccc
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

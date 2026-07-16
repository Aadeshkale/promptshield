"""
Heroku API key example.

Run from project root:
  python3 examples/heroku_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Heroku API Key:
HEROKU_API_KEY=12345678-1234-1234-1234-123456789abc

Heroku config:
  HEROKU_API_KEY=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  heroku_auth_token: 87654321-4321-4321-4321-abcdefabcdef
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

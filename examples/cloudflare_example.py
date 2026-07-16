"""
Cloudflare credentials example.

Run from project root:
  python3 examples/cloudflare_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Cloudflare Global API Key:
CLOUDFLARE_GLOBAL_API_KEY=abcdefghijklmnopqrstuvwxyzABCDEFGHIJK

Cloudflare API Token:
CLOUDFLARE_API_TOKEN=abcdefghijklmnopqrstuvwxyzABCDEFGH_ijklm

Cloudflare config:
  email: user@example.com
  api_key: abcdefghijklmnopqrstuvwxyzABCDEFGHIJK
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

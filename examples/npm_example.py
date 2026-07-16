"""
NPM token example.

Run from project root:
  python3 examples/npm_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
NPM access token:
NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ

.npmrc file:
  //registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnopqrstuvwxyzABCDEF

CI config:
  NPM_AUTH_TOKEN=npm_zyxwvutsrqponmlkjihgfedcbaABCDEFGHIJKLMNOPQ
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

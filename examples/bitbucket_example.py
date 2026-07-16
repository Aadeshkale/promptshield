"""
Bitbucket credentials example.

Run from project root:
  python3 examples/bitbucket_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
========================================
Bitbucket App Password
========================================

App Password:
abcdef12-34567890-abcdef12-34567890

========================================
Bitbucket OAuth Consumer Key
========================================

Consumer Key:
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

========================================
YAML Config
========================================

bitbucket:
  username: myuser
  app_password: abcdef12-34567890-abcdef12-34567890
  consumer_key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

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

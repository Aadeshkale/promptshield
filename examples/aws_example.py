"""
Simple example.

Run from project root:
  python3 examples/aws_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Deploy Terraform

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

Done.
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
    print(finding)

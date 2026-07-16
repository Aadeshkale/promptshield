"""
Discord bot token example.

Run from project root:
  python3 examples/discord_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Discord bot token:
DISCORD_TOKEN=NzI4NjE5MzU0Mjg3NTY4OTI5.XYZabc

Bot config:
  token: NTI3ODkwMTIzNDU2Nzg5MDEy.XYZdef
  client_id: 728619354287568929
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

"""
OpenAI API key example.

Run from project root:
  python3 examples/openai_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
OpenAI API Key (legacy):
OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGH

OpenAI Project API Key:
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST

Config:
  openai_api_key: sk-1234567890abcdef1234567890abcdef
  model: gpt-4
  temperature: 0.7
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

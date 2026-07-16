"""
Docker credentials example.

Run from project root:
  python3 examples/docker_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Docker Personal Access Token:
DOCKER_PAT=dckr_pat_abcdefghijklmnopqrABCDEFGHIJKLMNOPQRST

Docker config.json:
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dXNlcjpwYXNzd29yZA=="
    }
  }
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

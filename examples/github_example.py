"""
GitHub credentials example.

Run from project root:
  python3 examples/github_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
========================================
GitHub Personal Access Token (PAT)
========================================

Token:
ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN

OAuth Token:
gho_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN

User-to-Server Token:
ghu_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN

Server-to-Server Token:
ghs_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN

========================================
GitHub SSH Keys
========================================

SSH Deploy Key:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3G8F9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL

SSH Ed25519 Key:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGmVZxY8vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL9vL

========================================
YAML Config
========================================

github:
  token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
  repo: my-org/my-repo

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

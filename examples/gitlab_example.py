"""
GitLab credentials example.

Run from project root:
  python3 examples/gitlab_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
========================================
GitLab Personal Access Token (PAT)
========================================

Token:
glpat-abcdefghijklmnopqrstuvwxyz123456

========================================
GitLab Runner Token
========================================

Runner Token:
glrt-abcdefghijklmnopqrstuvwxyz123456

========================================
GitLab OAuth Access Token
========================================

OAuth Token:
gloas-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmn

========================================
YAML Config
========================================

gitlab:
  token: glpat-abcdefghijklmnopqrstuvwxyz123456
  project: my-group/my-project

CI/CD Variables:
  - CI_REGISTRY_PASSWORD: glpat-abcdefghijklmnopqrstuvwxyz123456

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

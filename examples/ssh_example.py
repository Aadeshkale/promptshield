"""
SSH private key example.

Run from project root:
  python3 examples/ssh_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
RSA Private Key:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0gD6I9h4ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop
qrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv
-----END RSA PRIVATE KEY-----

OpenSSH Private Key:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA0gD6I9h4ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs
-----END OPENSSH PRIVATE KEY-----

EC Private Key:
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIImABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
-----END EC PRIVATE KEY-----
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

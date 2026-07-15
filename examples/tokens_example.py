"""
Tokens example.

Run from project root:
  python3 examples/tokens_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
========================================
JWT Token
========================================

JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

========================================
Bearer Token
========================================

Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fakePayload.fakeSignature

========================================
OAuth Access Token
========================================

OAuth Token:
ya29.a0AfH6SMFakeOAuthAccessTokenabcdefghijklmnopqrstuvwxyz123456789

========================================
OAuth Refresh Token
========================================

Refresh Token:
1//0gFakeRefreshTokenABCDEFGHIJKLMNOPQRSTUVWXYZ123456789

========================================
Generic OAuth Header
========================================

Authorization: Bearer ya29.a0AfH6SMAnotherFakeAccessToken123456789abcdefghijklmnopqrstuvwxyz

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

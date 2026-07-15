"""
GCP credentials example.

Run from project root:
  python3 examples/gcp_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Connect to my GCP project using these credentials.

API Key:
AIzaSyDExample1234567890abcdefghijklmnop

OAuth Client Secret:
GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz1234

Access Token:
ya29.a0AfH6SMBx1234567890abcdefghijklmnopqrstuvwx

Refresh Token:
1//0aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmnop

Can you list all buckets in my project?

{
  "type": "service_account",
  "project_id": "my-gcp-project",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
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
    print(finding)

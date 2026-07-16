"""
Hardcoded credentials example.

Run from project root:
  python3 examples/credentials_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
========================================
Password assignments
========================================

password=supersecret123
PASSWORD = "myS3cur3P@ss!"
passwd = hunter2
pwd: admin123!
passphrase = "correct-horse-battery-staple"
secret = "a1b2c3d4e5f6g7h8"

========================================
Username assignments
========================================

username = admin@example.com
user_name = johndoe
user = developer1
login = api_service_account

========================================
Basic auth URLs
========================================

https://user:password123@example.internal.com
https://admin:adminpass%40123@host.company.com

========================================
Common config patterns
========================================

db_password = S3cretDBPass!
mysql_user = dba_admin
api_key = abcdefghijklmnopqrstuvwxyz123456

.env:
  DATABASE_PASSWORD=Db_P@ssw0rd!
  DB_USERNAME=app_user
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

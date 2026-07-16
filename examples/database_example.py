"""
Database connection string example.

Run from project root:
  python3 examples/database_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
PostgreSQL connection:
postgresql://admin:supersecret@db.example.com:5432/mydb

MySQL connection:
mysql://app_user:mysql_pass_123@mysql-host.local:3306/app_db

MongoDB connection:
mongodb+srv://dbadmin:securePass456@cluster0.abcd1.mongodb.net/myapp

Redis connection:
redis://default:redisPass789@cache.internal:6379

Postgres in config:
DATABASE_URL=postgres://readonly:readonlypass@rds.aws.com:5432/production
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

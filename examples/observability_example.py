"""
Observability API keys example (Datadog, New Relic, Sentry).

Run from project root:
  python3 examples/observability_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Datadog API:
  DD_API_KEY=1234567890abcdef1234567890abcdef
  DD_APP_KEY=aaaaaaaaaBBBBBBBBBccccccccccDDDDDDDDDD

New Relic:
  NEW_RELIC_LICENSE_KEY=NRAK-abcdefghijklmnopqrstuvwxyzABCDEFGHIJK

Sentry DSN:
  SENTRY_DSN=https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@o123456.ingest.sentry.io/1234567

Sentry config:
  sentry_dsn: https://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@o654321.ingest.sentry.io/7654321
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

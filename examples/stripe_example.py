"""
Stripe credentials example.

Run from project root:
  python3 examples/stripe_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Stripe Secret Keys:
  sk_live_abcdefghijklmnopqrstuvwxyzABCDEFGH
  sk_test_1234567890abcdef1234567890abcdef

Stripe Publishable Key:
  pk_live_abcdefghijklmnopqrstuvwxyzABCDEFGH

Stripe Restricted Key:
  rk_live_abcdefghijklmnopqrstuvwxyzABCDEFGH

Stripe Webhook Secret:
  whsec_abcdefghijklmnopqr

Config:
  stripe_secret_key: sk_live_zyxwvutsrqponmlkjihgfedcbaABCDEFGH
  stripe_webhook_secret: whsec_1234567890abcdef1234
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

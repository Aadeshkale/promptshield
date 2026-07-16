"""
Telegram bot token example.

Run from project root:
  python3 examples/telegram_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Telegram Bot Token (standard format):
  TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrSTUvwxYZabcdEFGhijkl

.env file:
  TELEGRAM_BOT_TOKEN=9876543210:ZYXwvuTSRqpoNMLKJIhgfedcbaBCDefGHIjkl

Config:
  telegram_token: 1122334455:AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtU
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

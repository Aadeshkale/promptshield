"""
PII Backend Example — Microsoft Presidio.

Demonstrates PII detection using the Presidio backend alongside
secret detection. Presidio uses NER-based analysis and supports
30+ entity types across multiple languages.

Requires: pip install presidio-analyzer
"""

from promptshield import PromptShield
from promptshield.backends import PresidioPIIBackend

# Presidio-only scan
shield = PromptShield(backends=[
    PresidioPIIBackend(score_threshold=0.5),
])

texts = [
    "Send report to john@doe.com, AWS key AKIAIOSFODNN7EXAMPLE",
    "Patient John Smith, SSN 234-56-7890, card 4111111111111111",
    "Contact Jane Doe at jane@example.com or call +1-800-555-0199",
    "Server 192.168.1.100 has API key sk-abc123xyz",
]

for text in texts:
    print(f"Input:  {text}")
    result = shield.scan(text)
    print(f"Output: {result.redacted_text}")
    for f in result.findings:
        print(f"  {f.detector:15s} {f.secret_type:20s} {f.value!r} (conf={f.confidence:.2f})")
    print()

# Presidio + secrets together
print("=" * 60)
print("Presidio + Secret detection combined:")
print("=" * 60)

from promptshield.backends import DetectSecretsBackend
from promptshield.detectors.aws import AWSAccessKeyDetector

combined = PromptShield(
    detectors=[AWSAccessKeyDetector()],
    backends=[PresidioPIIBackend(score_threshold=0.5)],
)

text = "Email admin@corp.com, AWS key AKIAIOSFODNN7EXAMPLE, IP 10.0.0.1"
result = combined.scan(text)
print(f"Input:  {text}")
print(f"Output: {result.redacted_text}")
for f in result.findings:
    print(f"  {f.detector:15s} {f.secret_type:20s} {f.value!r}")

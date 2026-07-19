"""
PII Detection Example.

Demonstrates detecting and redacting personally identifiable information
from text using PromptShield's built-in PII detectors.

PII detectors are opt-in — pass them in the `detectors` list.
"""

from promptshield import PromptShield
from promptshield.detectors.pii import (
    EmailDetector,
    PhoneDetector,
    SSNDetector,
    CreditCardDetector,
    IPv4Detector,
    IPv6Detector,
    USStreetAddressDetector,
)

pii_detectors = [
    EmailDetector(),
    PhoneDetector(),
    SSNDetector(),
    CreditCardDetector(),
    IPv4Detector(),
    IPv6Detector(),
    USStreetAddressDetector(),
]

shield = PromptShield(detectors=pii_detectors)

texts = [
    "Send the report to john.doe@example.com",
    "Call me at (555) 123-4567 or +1-800-555-0199",
    "SSN: 234-56-7890",
    "Card number: 4111 1111 1111 1111",
    "Server at 192.168.1.100 needs restart",
    "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "Mail to 123 Main Street, Springfield, IL 62701",
    (
        "Patient info: John Smith, SSN 234-56-7890, "
        "email john.smith@hospital.org, "
        "card 5500-0000-0000-0004, "
        "call (312) 555-7890 from 10.0.0.1"
    ),
]

for text in texts:
    print(f"Input:    {text}")
    result = shield.scan(text)
    print(f"Redacted: {result.redacted_text}")
    for f in result.findings:
        print(f"  -> {f.secret_type}: {f.value!r} (confidence={f.confidence:.2f})")
    print()

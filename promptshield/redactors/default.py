"""
Redactor modifies the original text.

Detectors NEVER modify text.
They only report:
  Found secret
  Position
  Replacement

Redactor performs the actual replacement.
"""


class DefaultRedactor:

    def redact(self, text, findings):
        # IMPORTANT: Replace from end of string.
        # Otherwise indexes become invalid.
        findings = sorted(
            findings,
            key=lambda finding: finding.start,
            reverse=True,
        )

        for finding in findings:
            text = (
                text[:finding.start]
                + finding.replacement
                + text[finding.end:]
            )

        return text

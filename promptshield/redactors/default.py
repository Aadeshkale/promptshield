"""
Redactor modifies the original text.

Detectors NEVER modify text.
They only report:
  Found secret
  Position
  Replacement

Redactor performs the actual replacement.
"""

import logging

logger = logging.getLogger(__name__)


class DefaultRedactor:

    def redact(self, text, findings):
        if not findings:
            return text

        # IMPORTANT: Replace from end of string.
        # Otherwise indexes become invalid.
        findings = sorted(
            findings,
            key=lambda finding: finding.start,
            reverse=True,
        )

        for finding in findings:
            logger.debug(
                "Redacting %s at [%d:%d] with %s",
                finding.secret_type, finding.start, finding.end, finding.replacement,
            )
            text = (
                text[:finding.start]
                + finding.replacement
                + text[finding.end:]
            )

        return text

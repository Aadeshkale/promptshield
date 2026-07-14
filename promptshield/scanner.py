"""
Scanner is the orchestrator.

It does NOT know AWS regex.
It does NOT know GitHub regex.
It simply asks every detector to scan.

Workflow

Input
   ↓
Detectors
   ↓
Policies
   ↓
Redactor
   ↓
ScanResult
"""

from promptshield.models import ScanResult
from promptshield.policies.default import DefaultPolicy
from promptshield.redactors.default import DefaultRedactor


class Scanner:

    def __init__(self, detectors):
        self.detectors = detectors
        self.policy = DefaultPolicy()
        self.redactor = DefaultRedactor()

    def scan(self, text):
        findings = []

        for detector in self.detectors:
            findings.extend(detector.detect(text))

        findings = self.policy.apply(findings)

        redacted = self.redactor.redact(text, findings)

        return ScanResult(
            original_text=text,
            redacted_text=redacted,
            findings=findings,
        )

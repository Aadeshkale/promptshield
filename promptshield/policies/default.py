"""
Policy decides what to do after detection.

Stage 4: Overlap Resolution.

Resolves overlapping findings using metadata:
  1. Verified findings first
  2. Higher specificity wins
  3. Higher confidence wins
  4. Earlier position wins
"""

from typing import List

from promptshield.models import Finding


class DefaultPolicy:

    def apply(self, findings: List[Finding]) -> List[Finding]:
        return self._remove_overlaps(findings)

    def _remove_overlaps(self, findings: List[Finding]) -> List[Finding]:
        if not findings:
            return findings

        findings = sorted(
            findings,
            key=lambda f: (
                -int(f.verified),
                -f.specificity,
                -f.confidence,
                f.start,
            )
        )

        resolved = []
        for finding in findings:
            overlaps = any(
                finding.start < accepted.end and finding.end > accepted.start
                for accepted in resolved
            )
            if not overlaps:
                resolved.append(finding)

        return sorted(resolved, key=lambda f: f.start)

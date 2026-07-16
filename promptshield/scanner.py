"""
Scanner orchestrates the three-stage detection pipeline.

Stage 1: Pattern Detection (detectors → candidates)
Stage 2: Context Enrichment (candidates → candidates + context)
Stage 3: Classification (candidates + context → findings)
Stage 4: Overlap Resolution (findings → resolved findings)

Input
   ↓
Detectors (regex → Candidates)
   ↓
Context Enricher (Candidates → Candidates + Context)
   ↓
Classifiers (Candidates + Context → Findings)
   ↓
Policy (overlap resolution)
   ↓
Redactor
   ↓
ScanResult
"""

from promptshield.context import ContextEnricher
from promptshield.classifiers.aws import AWSClassifier
from promptshield.classifiers.azure import AzureClassifier
from promptshield.classifiers.bitbucket import BitbucketClassifier
from promptshield.classifiers.docker import DockerClassifier
from promptshield.classifiers.gcp import GCPClassifier
from promptshield.classifiers.generic import GenericClassifier
from promptshield.classifiers.github import GitHubClassifier
from promptshield.classifiers.gitlab import GitLabClassifier
from promptshield.classifiers.oauth import OAuthClassifier
from promptshield.classifiers.slack import SlackClassifier
from promptshield.classifiers.ssh import SSHClassifier
from promptshield.classifiers.stripe import StripeClassifier
from promptshield.classifiers.telegram import TelegramClassifier
from promptshield.models import ScanResult
from promptshield.policies.default import DefaultPolicy
from promptshield.redactors.default import DefaultRedactor


class Scanner:

    def __init__(self, detectors):
        self.detectors = detectors
        self.enricher = ContextEnricher()
        self.classifiers = [
            GCPClassifier(),
            AWSClassifier(),
            AzureClassifier(),
            GitHubClassifier(),
            GitLabClassifier(),
            BitbucketClassifier(),
            DockerClassifier(),
            SlackClassifier(),
            SSHClassifier(),
            StripeClassifier(),
            TelegramClassifier(),
            OAuthClassifier(),
            GenericClassifier(),
        ]
        self.policy = DefaultPolicy()
        self.redactor = DefaultRedactor()

    def scan(self, text):
        # Stage 1: Pattern Detection
        candidates = []
        for detector in self.detectors:
            candidates.extend(detector.detect(text))

        # Stage 2: Context Enrichment
        enriched = [
            (candidate, self.enricher.enrich(text, candidate))
            for candidate in candidates
        ]

        # Stage 3: Classification
        findings = []
        for candidate, context in enriched:
            for classifier in self.classifiers:
                finding = classifier.classify(candidate, context)
                if finding:
                    findings.append(finding)
                    break

        # Stage 4: Overlap Resolution
        findings = self.policy.apply(findings)

        # Redactor
        redacted = self.redactor.redact(text, findings)

        return ScanResult(
            original_text=text,
            redacted_text=redacted,
            findings=findings,
        )

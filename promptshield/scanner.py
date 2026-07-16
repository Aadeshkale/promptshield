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
from promptshield.classifiers.cloudflare import CloudflareClassifier
from promptshield.classifiers.credentials import CredentialsClassifier
from promptshield.classifiers.database import DatabaseClassifier
from promptshield.classifiers.discord import DiscordClassifier
from promptshield.classifiers.docker import DockerClassifier
from promptshield.classifiers.gcp import GCPClassifier
from promptshield.classifiers.generic import GenericClassifier
from promptshield.classifiers.github import GitHubClassifier
from promptshield.classifiers.gitlab import GitLabClassifier
from promptshield.classifiers.heroku import HerokuClassifier
from promptshield.classifiers.npm import NPMClassifier
from promptshield.classifiers.oauth import OAuthClassifier
from promptshield.classifiers.observability import ObservabilityClassifier
from promptshield.classifiers.openai import OpenAIClassifier
from promptshield.classifiers.slack import SlackClassifier
from promptshield.classifiers.ssh import SSHClassifier
from promptshield.classifiers.stripe import StripeClassifier
from promptshield.classifiers.telegram import TelegramClassifier
from promptshield.classifiers.twilio import TwilioClassifier
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
            CloudflareClassifier(),
            CredentialsClassifier(),
            DatabaseClassifier(),
            DiscordClassifier(),
            DockerClassifier(),
            HerokuClassifier(),
            NPMClassifier(),
            ObservabilityClassifier(),
            OpenAIClassifier(),
            SlackClassifier(),
            SSHClassifier(),
            StripeClassifier(),
            TelegramClassifier(),
            TwilioClassifier(),
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

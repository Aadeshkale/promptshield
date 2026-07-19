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

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
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

logger = logging.getLogger(__name__)


class Scanner:

    def __init__(self, detectors, backends=None):
        self.detectors = detectors
        self.backends = backends or []
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

        logger.info(
            "Scanner initialized (%d detectors, %d classifiers, %d backends)",
            len(self.detectors), len(self.classifiers), len(self.backends),
        )

    def scan(self, text):
        logger.debug("Pipeline start (%d chars)", len(text))

        # Stage 1: Pattern Detection
        candidates = []
        for detector in self.detectors:
            try:
                candidates.extend(detector.detect(text))
            except Exception as e:
                logger.warning("Detector %s failed: %s", type(detector).__name__, e, exc_info=True)

        logger.debug("Stage 1: %d candidates from %d detectors", len(candidates), len(self.detectors))

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

        logger.debug("Stage 3: %d findings from %d candidates", len(findings), len(enriched))

        # Run backends in parallel
        if self.backends:
            with ThreadPoolExecutor(max_workers=len(self.backends)) as executor:
                futures = {
                    executor.submit(backend.scan, text): backend
                    for backend in self.backends
                }
                for future in as_completed(futures):
                    backend = futures[future]
                    try:
                        backend_findings = future.result()
                        findings.extend(backend_findings)
                        logger.debug("Backend %s returned %d findings", type(backend).__name__, len(backend_findings))
                    except Exception as e:
                        logger.warning(
                            "Secret backend %s failed: %s",
                            type(backend).__name__, e, exc_info=True,
                        )

        # Stage 4: Overlap Resolution
        pre_count = len(findings)
        findings = self.policy.apply(findings)
        if pre_count != len(findings):
            logger.debug("Policy resolved %d -> %d findings", pre_count, len(findings))

        # Redactor
        redacted = self.redactor.redact(text, findings)

        logger.debug("Pipeline complete: %d findings", len(findings))

        return ScanResult(
            original_text=text,
            redacted_text=redacted,
            findings=findings,
        )

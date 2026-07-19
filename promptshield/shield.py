import logging
from typing import List

from promptshield.detectors.aws import (
    AWSAccessKeyDetector,
    AWSTemporaryKeyDetector,
    AWSSecretKeyDetector,
    AWSSessionTokenDetector,
)
from promptshield.detectors.azure import (
    AzureClientSecretDetector,
    AzureStorageAccountKeyDetector,
    AzureSubscriptionIdDetector,
)
from promptshield.detectors.bitbucket import (
    BitbucketAppPasswordDetector,
    BitbucketOAuthConsumerKeyDetector,
)
from promptshield.detectors.cloudflare import (
    CloudflareGlobalAPIKeyDetector,
    CloudflareAPITokenDetector,
)
from promptshield.detectors.credentials import (
    PasswordAssignmentDetector,
    UsernameAssignmentDetector,
    BasicAuthURLDetector,
)
from promptshield.detectors.database import DatabaseConnectionStringDetector
from promptshield.detectors.discord import DiscordBotTokenDetector
from promptshield.detectors.docker import (
    DockerPATDetector,
    DockerHubTokenDetector,
)
from promptshield.detectors.gcp import (
    GCPAPIKeyDetector,
    GCPOAuthSecretDetector,
    GCPServiceAccountKeyDetector,
    GCPOAuthAccessTokenDetector,
    GCPRefreshTokenDetector,
)
from promptshield.detectors.github import (
    GitHubTokenDetector,
    GitHubSSHKeyDetector,
)
from promptshield.detectors.gitlab import (
    GitLabTokenDetector,
    GitLabRunnerTokenDetector,
    GitLabOTokenDetector,
)
from promptshield.detectors.heroku import HerokuAPIKeyDetector
from promptshield.detectors.npm import NPMAccessTokenDetector
from promptshield.detectors.observability import (
    DatadogAPIKeyDetector,
    DatadogAppKeyDetector,
    NewRelicAPIKeyDetector,
    SentryDSNDetector,
)
from promptshield.detectors.openai import (
    OpenAIAPIDetector,
    OpenAIProjectAPIDetector,
)
from promptshield.detectors.slack import (
    SlackBotTokenDetector,
    SlackUserTokenDetector,
    SlackWebhookDetector,
)
from promptshield.detectors.ssh import SSHPrivateKeyDetector
from promptshield.detectors.stripe import (
    StripeSecretKeyDetector,
    StripePublishableKeyDetector,
    StripeWebhookSecretDetector,
)
from promptshield.detectors.telegram import TelegramBotTokenDetector
from promptshield.detectors.tokens import (
    JWTTokenDetector,
    BearerTokenDetector,
    OAuthTokenDetector,
)
from promptshield.detectors.twilio import (
    TwilioAccountSIDDetector,
    TwilioAuthTokenDetector,
)
from promptshield.scanner import Scanner
from promptshield.exceptions import InjectionDetected, InvalidConfigurationError, ScanError

logger = logging.getLogger(__name__)

_INJECTION_MODES = {"flag", "redact", "block"}


class PromptShield:

    def __init__(self, detectors=None, backends=None, injection_backends=None, use_injection=False, injection_threshold=0.7, injection_mode="flag"):

        if injection_mode not in _INJECTION_MODES:
            raise InvalidConfigurationError(
                f"injection_mode must be one of {_INJECTION_MODES}, got {injection_mode!r}"
            )
        if not isinstance(injection_threshold, (int, float)):
            raise InvalidConfigurationError(
                f"injection_threshold must be a number, got {type(injection_threshold).__name__}"
            )
        if not (0.0 <= injection_threshold <= 1.0):
            raise InvalidConfigurationError(
                f"injection_threshold must be between 0.0 and 1.0, got {injection_threshold}"
            )

        self.use_injection = use_injection
        self.injection_threshold = injection_threshold
        self.injection_mode = injection_mode
        self.injection_backends = injection_backends or []
        self.injection_scanner = None

        logger.info(
            "Initializing PromptShield (injection=%s, threshold=%.2f, mode=%s, "
            "secret_backends=%d, injection_backends=%d)",
            use_injection, injection_threshold, injection_mode,
            len(backends) if backends else 0,
            len(self.injection_backends),
        )

        if use_injection:
            from promptshield.injection import InjectionScanner
            self.injection_scanner = InjectionScanner(
                threshold=injection_threshold,
                mode=injection_mode,
            )

        self.scanner = Scanner(
            detectors=detectors or [
                AWSAccessKeyDetector(),
                AWSTemporaryKeyDetector(),
                AWSSecretKeyDetector(),
                AWSSessionTokenDetector(),
                AzureClientSecretDetector(),
                AzureStorageAccountKeyDetector(),
                AzureSubscriptionIdDetector(),
                CloudflareGlobalAPIKeyDetector(),
                CloudflareAPITokenDetector(),
                PasswordAssignmentDetector(),
                UsernameAssignmentDetector(),
                BasicAuthURLDetector(),
                DatabaseConnectionStringDetector(),
                DiscordBotTokenDetector(),
                DockerPATDetector(),
                DockerHubTokenDetector(),
                GCPAPIKeyDetector(),
                GCPOAuthSecretDetector(),
                GCPServiceAccountKeyDetector(),
                GCPOAuthAccessTokenDetector(),
                GCPRefreshTokenDetector(),
                GitHubTokenDetector(),
                GitHubSSHKeyDetector(),
                GitLabTokenDetector(),
                GitLabRunnerTokenDetector(),
                GitLabOTokenDetector(),
                HerokuAPIKeyDetector(),
                NPMAccessTokenDetector(),
                DatadogAPIKeyDetector(),
                DatadogAppKeyDetector(),
                NewRelicAPIKeyDetector(),
                SentryDSNDetector(),
                OpenAIAPIDetector(),
                OpenAIProjectAPIDetector(),
                BitbucketAppPasswordDetector(),
                BitbucketOAuthConsumerKeyDetector(),
                SlackBotTokenDetector(),
                SlackUserTokenDetector(),
                SlackWebhookDetector(),
                SSHPrivateKeyDetector(),
                StripeSecretKeyDetector(),
                StripePublishableKeyDetector(),
                StripeWebhookSecretDetector(),
                TelegramBotTokenDetector(),
                TwilioAccountSIDDetector(),
                TwilioAuthTokenDetector(),
                JWTTokenDetector(),
                BearerTokenDetector(),
                OAuthTokenDetector(),
            ],
            backends=backends,
        )

        logger.debug(
            "PromptShield ready (%d detectors, %d classifiers)",
            len(self.scanner.detectors), len(self.scanner.classifiers),
        )

    def scan(self, text):
        if not isinstance(text, str):
            raise InvalidConfigurationError(
                f"scan() requires a string, got {type(text).__name__}"
            )

        logger.debug("Scanning %d chars", len(text))

        result = self.scanner.scan(text)

        injection_results = []

        if self.use_injection and self.injection_scanner:
            injection_results.append(self.injection_scanner.scan(text))

        if self.injection_backends:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=len(self.injection_backends)) as executor:
                futures = {
                    executor.submit(backend.scan, text): backend
                    for backend in self.injection_backends
                }
                for future in as_completed(futures):
                    backend = futures[future]
                    try:
                        injection_results.append(future.result())
                    except Exception as e:
                        logger.warning(
                            "Injection backend %s failed: %s",
                            type(backend).__name__, e,
                            exc_info=True,
                        )

        if injection_results:
            result.injection = self._merge_injection_results(injection_results)

            logger.debug(
                "Injection result: threat=%.4f, blocked=%s, patterns=%s",
                result.injection.threat_score,
                result.injection.blocked,
                result.injection.patterns_matched,
            )

            if result.injection.blocked and self.injection_mode == "block":
                raise InjectionDetected(
                    threat_score=result.injection.threat_score,
                    patterns_matched=result.injection.patterns_matched,
                )

        logger.info(
            "Scan complete: %d findings, injection=%s",
            len(result.findings),
            f"threat={result.injection.threat_score:.2f}" if result.injection else "none",
        )

        return result

    def _merge_injection_results(self, results):
        from promptshield.models import InjectionResult

        max_score = 0.0
        blocked = False
        all_patterns = []
        all_scores = {}
        action = results[0].action

        for r in results:
            max_score = max(max_score, r.threat_score)
            blocked = blocked or r.blocked
            for p in r.patterns_matched:
                if p not in all_patterns:
                    all_patterns.append(p)
            all_scores.update(r.scores)

        merged = InjectionResult(
            threat_score=round(max_score, 4),
            blocked=blocked,
            scores=all_scores,
            patterns_matched=all_patterns,
            action=action,
        )

        logger.debug(
            "Merged %d injection results -> threat=%.4f, blocked=%s",
            len(results), merged.threat_score, merged.blocked,
        )

        return merged

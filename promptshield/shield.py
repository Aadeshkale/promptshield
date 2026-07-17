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
from promptshield.exceptions import InjectionDetected


class PromptShield:

    def __init__(self, detectors=None, use_injection=False, injection_threshold=0.7, injection_mode="flag"):

        self.use_injection = use_injection
        self.injection_threshold = injection_threshold
        self.injection_mode = injection_mode
        self.injection_scanner = None

        if use_injection:
            from promptshield.injection import InjectionScanner
            self.injection_scanner = InjectionScanner(
                threshold=injection_threshold,
                mode=injection_mode,
            )

        self.scanner = Scanner(
            detectors or [
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
            ]
        )

    def scan(self, text):

        result = self.scanner.scan(text)

        if self.use_injection and self.injection_scanner:
            result.injection = self.injection_scanner.scan(text)

            if result.injection.blocked and self.injection_mode == "block":
                raise InjectionDetected(
                    threat_score=result.injection.threat_score,
                    patterns_matched=result.injection.patterns_matched,
                )

        return result

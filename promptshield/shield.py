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
from promptshield.scanner import Scanner


class PromptShield:

    def __init__(self, detectors=None):

        self.scanner = Scanner(
            detectors or [
                AWSAccessKeyDetector(),
                AWSTemporaryKeyDetector(),
                AWSSecretKeyDetector(),
                AWSSessionTokenDetector(),
                AzureClientSecretDetector(),
                AzureStorageAccountKeyDetector(),
                AzureSubscriptionIdDetector(),
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
                BitbucketAppPasswordDetector(),
                BitbucketOAuthConsumerKeyDetector(),
                DockerPATDetector(),
                DockerHubTokenDetector(),
                SlackBotTokenDetector(),
                SlackUserTokenDetector(),
                SlackWebhookDetector(),
                SSHPrivateKeyDetector(),
                StripeSecretKeyDetector(),
                StripePublishableKeyDetector(),
                StripeWebhookSecretDetector(),
                TelegramBotTokenDetector(),
                JWTTokenDetector(),
                BearerTokenDetector(),
                OAuthTokenDetector(),
            ]
        )

    def scan(self, text):

        return self.scanner.scan(text)
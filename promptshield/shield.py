from promptshield.detectors.aws import (
    AWSAccessKeyDetector,
    AWSTemporaryKeyDetector,
    AWSSecretKeyDetector,
    AWSSessionTokenDetector,
)
from promptshield.detectors.gcp import (
    GCPAPIKeyDetector,
    GCPOAuthSecretDetector,
    GCPServiceAccountKeyDetector,
    GCPOAuthAccessTokenDetector,
    GCPRefreshTokenDetector,
)
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
                GCPAPIKeyDetector(),
                GCPOAuthSecretDetector(),
                GCPServiceAccountKeyDetector(),
                GCPOAuthAccessTokenDetector(),
                GCPRefreshTokenDetector(),
                JWTTokenDetector(),
                BearerTokenDetector(),
                OAuthTokenDetector(),
            ]
        )

    def scan(self, text):

        return self.scanner.scan(text)
from promptshield.detectors.aws import AWSAccessKeyDetector
from promptshield.scanner import Scanner


class PromptShield:

    def __init__(self, detectors=None):

        self.scanner = Scanner(
            detectors or [
                AWSAccessKeyDetector(),
            ]
        )

    def scan(self, text):

        return self.scanner.scan(text)
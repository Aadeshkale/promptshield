import logging

from promptshield.shield import PromptShield
from promptshield.exceptions import (
    PromptShieldError,
    InjectionDetected,
    InvalidConfigurationError,
    ScanError,
)

logging.getLogger("promptshield").addHandler(logging.NullHandler())

"""
Base class for third-party secret scanner backends.

Each backend wraps an external scanner and converts its findings
to PromptShield's Finding format.
"""

from abc import ABC, abstractmethod
from typing import List

from promptshield.models import Finding


class BackendScanner(ABC):

    @abstractmethod
    def scan(self, text: str) -> List[Finding]:
        """
        Scan text and return a list of Finding objects.

        Backends bypass the detector/classifier pipeline and produce
        finished Findings directly. If the backend dependency is not
        installed, return an empty list.
        """
        pass

"""
Every detector MUST inherit from BaseDetector.

This ensures every detector has the same interface.

AWS detector
GitHub detector
OpenAI detector

all implement

detect(text)
"""

from abc import ABC, abstractmethod
from typing import List

from promptshield.models import Finding


class BaseDetector(ABC):

    @abstractmethod
    def detect(self, text: str) -> List[Finding]:
        """
        Scan text and return a list of Finding objects.

        If nothing is found, return an empty list.
        """
        pass
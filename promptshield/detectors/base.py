"""
Every detector MUST inherit from BaseDetector.

This ensures every detector has the same interface.

Stage 1: Pattern Detection
  Detectors are pure regex matchers.
  They return Candidate objects (raw matches).
  Context enrichment and classification happen in later stages.
"""

from abc import ABC, abstractmethod
from typing import List

from promptshield.models import Candidate


class BaseDetector(ABC):

    @abstractmethod
    def detect(self, text: str) -> List[Candidate]:
        """
        Scan text and return a list of Candidate objects.

        If nothing is found, return an empty list.
        """
        pass

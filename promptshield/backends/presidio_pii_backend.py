"""
Backend wrapper for Microsoft Presidio PII analyzer.

Detects personally identifiable information using Presidio's NER-based
and pattern-based PII recognizers. Supports 30+ entity types across
multiple languages.

Requires: pip install presidio-analyzer
"""

import logging
from typing import List, Optional

from promptshield.backends.base import BackendScanner
from promptshield.models import Finding

log = logging.getLogger(__name__)


class PresidioPIIBackend(BackendScanner):
    """Scan text for PII using Microsoft Presidio."""

    def __init__(
        self,
        score_threshold: float = 0.5,
        language: str = "en",
        entities: Optional[List[str]] = None,
        confidence: float = 0.80,
        specificity: int = 85,
    ):
        self.score_threshold = score_threshold
        self.language = language
        self.entities = entities
        self.confidence = confidence
        self.specificity = specificity

    def _create_analyzer(self):
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": self.language, "model_name": "en_core_web_sm"}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
        return AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=[self.language],
        )

    def scan(self, text: str) -> List[Finding]:
        try:
            analyzer = self._create_analyzer()
        except Exception as e:
            log.warning(
                "presidio-analyzer failed to initialize: %s. "
                "Install with: pip install presidio-analyzer",
                e,
            )
            return []

        kwargs = {
            "text": text,
            "language": self.language,
            "score_threshold": self.score_threshold,
        }
        if self.entities:
            kwargs["entities"] = self.entities

        try:
            results = analyzer.analyze(**kwargs)
        except Exception as e:
            log.warning("Presidio analysis failed: %s", e)
            return []

        findings: List[Finding] = []
        for r in results:
            value = text[r.start:r.end]
            findings.append(Finding(
                detector="presidio",
                secret_type=r.entity_type,
                value=value,
                start=r.start,
                end=r.end,
                replacement=f"<{r.entity_type}>",
                confidence=round(r.score, 4),
                specificity=self.specificity,
            ))

        log.debug("Presidio detected %d PII entities", len(findings))
        return findings

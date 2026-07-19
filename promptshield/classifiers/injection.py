"""
Injection Classifiers.

Classifies injection candidates using pattern matching and optional ML.
"""

import logging

from promptshield.classifiers import BaseClassifier
from promptshield.models import Candidate, Context, Finding

logger = logging.getLogger(__name__)


INJECTION_PATTERNS = {
    "INJECTION_INSTRUCTION_OVERRIDE": {
        "secret_type": "PROMPT_INJECTION",
        "base_confidence": 0.70,
        "base_specificity": 80,
        "replacement": "<INJECTION_BLOCKED>",
    },
    "INJECTION_ROLE_HIJACK": {
        "secret_type": "PROMPT_INJECTION",
        "base_confidence": 0.75,
        "base_specificity": 85,
        "replacement": "<INJECTION_BLOCKED>",
    },
    "INJECTION_SYSTEM_EXTRACTION": {
        "secret_type": "PROMPT_INJECTION",
        "base_confidence": 0.80,
        "base_specificity": 90,
        "replacement": "<INJECTION_BLOCKED>",
    },
    "INJECTION_DELIMITER_INJECTION": {
        "secret_type": "PROMPT_INJECTION",
        "base_confidence": 0.85,
        "base_specificity": 95,
        "replacement": "<INJECTION_BLOCKED>",
    },
    "INJECTION_NEW_INSTRUCTIONS": {
        "secret_type": "PROMPT_INJECTION",
        "base_confidence": 0.65,
        "base_specificity": 70,
        "replacement": "<INJECTION_BLOCKED>",
    },
    "INJECTION_DEVELOPER_MODE": {
        "secret_type": "PROMPT_INJECTION",
        "base_confidence": 0.80,
        "base_specificity": 90,
        "replacement": "<INJECTION_BLOCKED>",
    },
    "INJECTION_ENCODED_PAYLOAD": {
        "secret_type": "ENCODED_PAYLOAD",
        "base_confidence": 0.40,
        "base_specificity": 30,
        "replacement": "<ENCODED_PAYLOAD_BLOCKED>",
    },
    "INJECTION_DATA_EXFIL": {
        "secret_type": "DATA_EXFILTRATION",
        "base_confidence": 0.90,
        "base_specificity": 95,
        "replacement": "<EXFIL_BLOCKED>",
    },
}


class InjectionPatternClassifier(BaseClassifier):
    """
    Classifies injection candidates using pattern metadata and context.
    """

    def classify(self, candidate, context):
        pattern_info = INJECTION_PATTERNS.get(candidate.pattern_name)
        if not pattern_info:
            return None

        confidence = pattern_info["base_confidence"]
        confidence += self._entropy_boost(candidate.value)

        return Finding(
            detector="injection_pattern",
            secret_type=pattern_info["secret_type"],
            value=candidate.value,
            start=candidate.start,
            end=candidate.end,
            replacement=pattern_info["replacement"],
            confidence=min(confidence, 1.0),
            specificity=pattern_info["base_specificity"],
            context_before=context.preceding,
            context_after=context.following,
            line=context.line_number,
            column=candidate.start - context.line.rfind('\n') - 1,
        )


class InjectionMLClassifier:
    """
    ML-based injection classifier using DeBERTa.

    Requires: pip install promptshield[injection]
    """

    def __init__(self, model_name="protectai/deberta-v3-base-prompt-injection-v2"):
        self._classifier = None
        self._model_name = model_name

    def _load_model(self):
        if self._classifier is not None:
            return True
        try:
            from transformers import pipeline
            logger.info("Loading ML injection classifier: %s", self._model_name)
            self._classifier = pipeline(
                "text-classification",
                model=self._model_name,
                top_k=None,
            )
            logger.info("ML injection classifier loaded successfully")
            return True
        except ImportError:
            logger.debug("transformers not installed, ML classifier unavailable")
            return False
        except OSError as e:
            logger.warning("ML classifier model load failed: %s", e)
            return False

    def is_available(self):
        return self._load_model()

    def classify(self, text):
        if not self._load_model():
            return None

        truncated = text[:512]
        results = self._classifier(truncated)

        for label_info in results[0]:
            if label_info["label"] == "INJECTION":
                return label_info["score"]
        return 0.0

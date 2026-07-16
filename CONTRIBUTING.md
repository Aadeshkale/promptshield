# Contributing

## Architecture Overview

PromptShield uses a 4-stage pipeline:

```
Input text
   |
[Stage 1] Detectors (regex) -> Candidates
   |
[Stage 2] ContextEnricher -> Candidate + Context
   |
[Stage 3] Classifiers -> Findings
   |
[Stage 4] Policy (overlap resolution) -> Redactor -> ScanResult
```

### Stage 1: Detectors

Every detector inherits `BaseDetector` (`promptshield/detectors/base.py`) and implements:

```python
class MyDetector(BaseDetector):
    PATTERN = re.compile(r"...")
    PATTERN_NAME = "MY_PATTERN"

    def detect(self, text: str) -> List[Candidate]:
        ...
```

- `detect()` returns `List[Candidate]` — raw regex matches with position.
- Detectors **never** modify text.

**Registration**: import the detector in `promptshield/shield.py` and add an instance to the `detectors` list.

### Stage 2: Context Enricher

`ContextEnricher` (`promptshield/context.py`) extracts 30 chars of context before/after each candidate, the full line, and adjacent line. Used automatically by `Scanner` — no action needed when adding a new provider.

### Stage 3: Classifiers

Every classifier inherits `BaseClassifier` (`promptshield/classifiers/__init__.py`) and implements:

```python
class MyClassifier(BaseClassifier):
    PATTERNS = {
        "MY_PATTERN": {
            "secret_type": "MY_SECRET",
            "base_confidence": 0.50,
            "base_specificity": 95,
            "replacement": "<REDACTED>",
        },
    }
    CONTEXT_KEYWORDS = ["myprovider"]

    def classify(self, candidate, context) -> Finding | None:
        ...
```

- `classify()` matches `candidate.pattern_name` against `PATTERNS`, computes confidence, and returns a `Finding` or `None`.
- Base class provides `_context_boost()`, `_entropy_boost()`, and `_calculate_entropy()`.
- **Context-requiring classifiers** return `None` unless a keyword from `CONTEXT_KEYWORDS` appears in the surrounding context.
- First matching classifier wins (classifier list order = priority).

**Registration**: import the classifier in `promptshield/scanner.py` and add an instance to the `classifiers` list.

### Stage 4: Policy + Redactor

- `DefaultPolicy` (`promptshield/policies/default.py`) resolves overlapping findings by specificity, confidence, and position.
- `DefaultRedactor` (`promptshield/redactors/default.py`) replaces findings from end to start to preserve indices.

## Data Models

| Class | Stage | Fields |
|---|---|---|
| `Candidate` | 1 | `value`, `start`, `end`, `pattern_name` |
| `Context` | 2 | `preceding`, `following`, `line`, `line_number`, `preceding_line`, `env_var`, `header` |
| `Finding` | 3 | `detector`, `secret_type`, `value`, `start`, `end`, `replacement`, `confidence`, `specificity`, `context_before`, `context_after`, `line`, `column`, `verified` |
| `ScanResult` | final | `original_text`, `redacted_text`, `findings` |

## Adding a New Provider

1. Create `promptshield/detectors/<provider>.py` with one or more `BaseDetector` subclasses.
2. Create `promptshield/classifiers/<provider>.py` with a `BaseClassifier` subclass mapping each `PATTERN_NAME`.
3. Create `examples/<provider>_example.py` to verify detection.
4. Register the detector(s) in `promptshield/shield.py`.
5. Register the classifier in `promptshield/scanner.py`.
6. Run the example: `python3 examples/<provider>_example.py`.

### False Positive Prevention

- `AWSSecretKeyDetector` uses a loose 40-char alphanumeric pattern. Add new token prefixes to `TOKEN_PREFIXES` and `EXCLUDE_PREFIXES` in `promptshield/detectors/aws.py` to prevent overlap.
- `BitbucketOAuthConsumerKeyDetector` matches any 32-char alphanumeric. Exclude all-hex strings to avoid Datadog key false positives (see `promptshield/detectors/bitbucket.py:47`).
- For ambiguous patterns (UUIDs, 32-40 char random strings), use a **context-requiring classifier** — return `None` if no keyword matches.

## Project Conventions

- **No comments** in production code unless absolutely necessary for clarity.
- Follow existing import and whitespace style exactly.
- Detectors live in `promptshield/detectors/`, classifiers in `promptshield/classifiers/`.
- Each provider gets its own file in both directories.
- One `examples/` file per provider, runnable with `python3 examples/<name>.py`.

"""
Stage 2: Context Enrichment.

Extracts surrounding information for each candidate.
Used by classifiers to determine confidence and specificity.
"""

from promptshield.models import Candidate, Context


class ContextEnricher:
    """Extracts surrounding context for each candidate."""

    CONTEXT_WINDOW = 30

    def enrich(self, text: str, candidate: Candidate) -> Context:
        start = candidate.start
        end = candidate.end

        preceding = text[max(0, start - self.CONTEXT_WINDOW):start]
        following = text[end:min(len(text), end + self.CONTEXT_WINDOW)]

        line_start = text.rfind('\n', 0, start) + 1
        line_end = text.find('\n', end)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        line_number = text[:start].count('\n') + 1

        prev_line_end = text.rfind('\n', 0, line_start - 1)
        if prev_line_end == -1:
            preceding_line = ""
        else:
            preceding_line = text[prev_line_end + 1:line_start - 1]

        env_var = ""
        if '=' in preceding:
            env_var = preceding.split('=')[-1].strip()

        header = ""
        if any(kw in preceding for kw in ['Bearer', 'OAuth', 'Authorization']):
            header = preceding.split(':')[-1].strip()

        return Context(
            preceding=preceding,
            following=following,
            line=line,
            line_number=line_number,
            preceding_line=preceding_line,
            env_var=env_var,
            header=header,
        )

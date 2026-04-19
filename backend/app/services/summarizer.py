"""Preview summary generator.

Heuristic summarizer (no LLM dependency) — pulls the first informative
sentence(s) from the description and truncates to ~300 chars. Swap for
an LLM-based summarizer later by replacing `generate_summary`.
"""
from __future__ import annotations

import re

MAX_LEN = 300
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


def generate_summary(title: str, description: str) -> str:
    if not description:
        return title[:MAX_LEN]

    sentences = _SENT_SPLIT.split(description.strip())
    buf: list[str] = []
    total = 0
    for s in sentences:
        if total + len(s) > MAX_LEN:
            break
        buf.append(s.strip())
        total += len(s) + 1

    summary = " ".join(buf) if buf else description[:MAX_LEN]
    return summary[:MAX_LEN]

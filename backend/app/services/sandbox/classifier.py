"""Map a Vulnerability to a sandbox lab kind.

Rule-based first pass — looks at attached vulnerability-type CWEs/names and
falls back to keywords in the title/description. Returns ``None`` when no
known lab fits, in which case the API surfaces a "not yet supported" error.

When more lab kinds land here, keep this purely rule-based (cheap and
deterministic). AI-based classification can be layered on later for the
ambiguous cases.
"""
from __future__ import annotations

from app.models import Vulnerability

# CWE IDs that map to each lab kind. Only the most common ones are listed —
# anything else falls through to keyword matching.
_CWE_TO_KIND: dict[str, str] = {
    "CWE-79": "xss",  # Improper Neutralization of Input During Web Page Generation
    "CWE-80": "xss",
    "CWE-83": "xss",
    "CWE-87": "xss",
}

# Keyword patterns (lowercased substrings) per lab kind. Order in the dict
# is the lookup priority when multiple match.
_KEYWORDS: dict[str, tuple[str, ...]] = {
    "xss": (
        "cross-site scripting",
        "cross site scripting",
        "xss",
        "stored script",
        "reflected script",
    ),
}


def classify_vulnerability(vuln: Vulnerability) -> str | None:
    """Return the lab kind (e.g. ``"xss"``) that best matches *vuln*, or ``None``."""
    for vt in vuln.types or []:
        if vt.cwe_id and vt.cwe_id.upper() in _CWE_TO_KIND:
            return _CWE_TO_KIND[vt.cwe_id.upper()]
        if vt.name:
            lower = vt.name.lower()
            for kind, words in _KEYWORDS.items():
                if any(w in lower for w in words):
                    return kind

    haystack = f"{vuln.title or ''}\n{vuln.description or ''}".lower()
    for kind, words in _KEYWORDS.items():
        if any(w in haystack for w in words):
            return kind
    return None

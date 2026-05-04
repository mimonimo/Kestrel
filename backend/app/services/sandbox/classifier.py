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
    # XSS family
    "CWE-79": "xss",  # Improper Neutralization of Input During Web Page Generation
    "CWE-80": "xss",
    "CWE-83": "xss",
    "CWE-87": "xss",
    # Command injection / RCE
    "CWE-77": "rce",  # Improper Neutralization of Special Elements used in a Command
    "CWE-78": "rce",  # OS Command Injection
    "CWE-94": "rce",  # Improper Control of Generation of Code
    # SQL injection
    "CWE-89": "sqli",  # SQL Injection
    "CWE-564": "sqli",  # SQL Injection: Hibernate
    # Server-Side Template Injection
    "CWE-1336": "ssti",
    "CWE-95": "ssti",  # Eval Injection (close cousin)
    # Path traversal / LFI
    "CWE-22": "path-traversal",  # Path Traversal
    "CWE-23": "path-traversal",  # Relative Path Traversal
    "CWE-36": "path-traversal",  # Absolute Path Traversal
    "CWE-73": "path-traversal",  # External Control of File Name or Path
    # SSRF
    "CWE-918": "ssrf",  # Server-Side Request Forgery
    # Auth-bypass / broken access control. No generic Flask lab for this
    # class yet (PR 9-X), so resolver step 3 will pass through to AI
    # synthesis instead — the synthesizer prompt now includes auth-bypass
    # in its known_kinds guide so the LLM can produce a matching lab.
    "CWE-287": "auth-bypass",  # Improper Authentication
    "CWE-306": "auth-bypass",  # Missing Authentication for Critical Function
    "CWE-425": "auth-bypass",  # Direct Request ('Forced Browsing')
    "CWE-639": "auth-bypass",  # Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-863": "auth-bypass",  # Incorrect Authorization
    "CWE-862": "auth-bypass",  # Missing Authorization
}

# Keyword patterns (lowercased substrings) per lab kind. Lookup order
# matters when a CVE description matches multiple — we prefer the more
# *specific* class first (e.g. "command injection" before "injection"),
# so list the most-specific kinds first.
_KEYWORDS: dict[str, tuple[str, ...]] = {
    "rce": (
        "command injection",
        "os command",
        "remote code execution",
        "rce",
        "shell injection",
        "code execution",
        "arbitrary command",
    ),
    "sqli": (
        "sql injection",
        "sqli",
        "blind sql",
        "boolean-based sql",
        "time-based sql",
        "union-based sql",
    ),
    "ssti": (
        "template injection",
        "ssti",
        "jinja",
        "twig template",
        "freemarker",
    ),
    "path-traversal": (
        "path traversal",
        "directory traversal",
        "lfi",
        "local file inclusion",
        "arbitrary file read",
        "../../",
    ),
    "ssrf": (
        "server-side request forgery",
        "server side request forgery",
        "ssrf",
        "blind ssrf",
    ),
    "auth-bypass": (
        "authentication bypass",
        "auth bypass",
        "improper authentication",
        "missing authentication",
        "broken access control",
        "incorrect authorization",
        "missing authorization",
        "idor",
        "insecure direct object reference",
        "forced browsing",
    ),
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

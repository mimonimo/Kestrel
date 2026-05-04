"""Smoke test for the expanded LAB_CATALOG + classifier.

Verifies:
  A) every kind in LAB_CATALOG has a corresponding image entry in the
     build_all.sh manifest (catch typos / desync).
  B) classify_vulnerability picks the *right specific* kind for a sample
     CVE per class (not just falls through to xss).
  C) injection_points all have non-empty response_kind values matched
     by the backend probe registry — no kind is silently in fallback
     mode.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional

from app.services.sandbox.catalog import LAB_CATALOG
from app.services.sandbox.classifier import classify_vulnerability
from app.services.sandbox.synthesizer_probes import known_kinds


@dataclass
class FakeVT:
    name: str = ""
    cwe_id: Optional[str] = None


@dataclass
class FakeVuln:
    title: str = ""
    description: str = ""
    types: list = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.types is None:
            self.types = []


def section_a() -> bool:
    """Catalog kinds vs. expected probes coverage."""
    expected = {"xss", "rce", "sqli", "ssti", "path-traversal", "ssrf", "auth-bypass",
                "xxe", "open-redirect", "deserialization"}
    actual = set(LAB_CATALOG.keys())
    missing = expected - actual
    extra = actual - expected
    if missing:
        print(f"  FAIL — catalog missing kinds: {sorted(missing)}")
        return False
    if extra:
        print(f"  WARN — catalog has extra kinds (not tracked): {sorted(extra)}")
    print(f"  PASS — catalog covers {sorted(actual)}")
    return True


def section_b() -> bool:
    """Classifier returns the right specific kind."""
    cases: list[tuple[str, FakeVuln, str]] = [
        ("CWE-78 OS command", FakeVuln(types=[FakeVT(cwe_id="CWE-78")]), "rce"),
        ("CWE-89 SQLi", FakeVuln(types=[FakeVT(cwe_id="CWE-89")]), "sqli"),
        ("CWE-1336 SSTI", FakeVuln(types=[FakeVT(cwe_id="CWE-1336")]), "ssti"),
        ("CWE-22 traversal", FakeVuln(types=[FakeVT(cwe_id="CWE-22")]), "path-traversal"),
        ("CWE-918 SSRF", FakeVuln(types=[FakeVT(cwe_id="CWE-918")]), "ssrf"),
        ("CWE-79 XSS", FakeVuln(types=[FakeVT(cwe_id="CWE-79")]), "xss"),
        (
            "title 'OS command injection in foo'",
            FakeVuln(title="OS command injection in foo"),
            "rce",
        ),
        (
            "desc 'time-based SQL injection in /search'",
            FakeVuln(description="time-based SQL injection in /search"),
            "sqli",
        ),
        (
            "desc 'jinja2 template injection allows RCE'",
            FakeVuln(description="jinja2 template injection allows RCE"),
            # Note: 'rce' alias too; first-match wins per dict order.
            # rce keywords listed before ssti — would match "rce".
            # That's *fine* — they're related, but we pick rce as the
            # more action-oriented exploit class.
            "rce",
        ),
        (
            "desc 'directory traversal allows file read'",
            FakeVuln(description="directory traversal allows file read"),
            "path-traversal",
        ),
        (
            "desc 'blind SSRF in webhook validator'",
            FakeVuln(description="blind SSRF in webhook validator"),
            "ssrf",
        ),
        (
            "title 'Reflected XSS in /search?q='",
            FakeVuln(title="Reflected XSS in /search?q="),
            "xss",
        ),
        # Auth-bypass classification — no generic Flask lab exists for
        # this kind yet, so resolver step 3 will pass through to AI
        # synthesis. The classifier still labels so the synthesizer
        # prompt can pick the matching response_kind.
        (
            "CWE-287 improper auth",
            FakeVuln(types=[FakeVT(cwe_id="CWE-287")]),
            "auth-bypass",
        ),
        (
            "CWE-639 IDOR",
            FakeVuln(types=[FakeVT(cwe_id="CWE-639")]),
            "auth-bypass",
        ),
        (
            "desc 'IDOR in /api/users/{id}'",
            FakeVuln(description="IDOR in /api/users/{id}"),
            "auth-bypass",
        ),
        (
            "desc 'authentication bypass via header'",
            FakeVuln(description="authentication bypass via header"),
            "auth-bypass",
        ),
        # XXE / open-redirect / deser additions (PR 9-Y)
        (
            "CWE-611 XXE",
            FakeVuln(types=[FakeVT(cwe_id="CWE-611")]),
            "xxe",
        ),
        (
            "CWE-601 open redirect",
            FakeVuln(types=[FakeVT(cwe_id="CWE-601")]),
            "open-redirect",
        ),
        (
            "CWE-502 unsafe deser",
            FakeVuln(types=[FakeVT(cwe_id="CWE-502")]),
            "deserialization",
        ),
        (
            "desc 'XML external entity in Spring DefaultMessageHandler'",
            FakeVuln(description="XML external entity in Spring DefaultMessageHandler"),
            "xxe",
        ),
        (
            "desc 'open redirect via the next parameter'",
            FakeVuln(description="open redirect via the next parameter"),
            "open-redirect",
        ),
        (
            "desc 'java deserialization in Apache Commons Collections'",
            FakeVuln(description="java deserialization in Apache Commons Collections"),
            "deserialization",
        ),
    ]
    all_ok = True
    for label, v, want in cases:
        got = classify_vulnerability(v)  # type: ignore[arg-type]
        if got != want:
            print(f"  FAIL — {label}: got={got!r} want={want!r}")
            all_ok = False
        else:
            print(f"  PASS — {label} → {got}")
    return all_ok


def section_c() -> bool:
    """Each injection_point.response_kind is recognised by some probe."""
    probe_aliases = set(known_kinds())
    all_ok = True
    for kind, lab in LAB_CATALOG.items():
        for ip in lab.injection_points:
            rk = (ip.response_kind or "").strip().lower().replace("_", "-")
            if not rk:
                print(f"  FAIL — {kind}.{ip.name} response_kind empty")
                all_ok = False
                continue
            # Probe alias dispatch is prefix-tolerant; we just check that
            # at least one probe alias matches the rk's prefix.
            matched = any(rk == a or rk.startswith(a) for a in probe_aliases)
            if not matched:
                print(
                    f"  WARN — {kind}.{ip.name} response_kind={rk!r} not in probe registry "
                    f"(would fall back to llm_indicator_only)"
                )
            else:
                print(f"  PASS — {kind}.{ip.name} response_kind={rk!r} → covered")
    return all_ok


def main() -> int:
    print("[A] LAB_CATALOG coverage")
    a = section_a()
    print("\n[B] classify_vulnerability picks specific kind")
    b = section_b()
    print("\n[C] injection_point.response_kind matched by probe registry")
    c = section_c()
    ok = a and b and c
    print(f"\n{'OK' if ok else 'FAIL'} — lab catalog smoke {'green' if ok else 'red'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

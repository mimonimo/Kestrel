"""PR 9-L smoke — backend probes + tightened indicator gate + verdict aggregation.

Pure-python: monkey-patches ``proxy_request`` and ``exec_in_lab`` so we can
exercise the probe library without docker. Three blocks:

  A) ``_validate_parsed`` rejects each echo-trap shape we care about
     (short indicator, indicator==payload, indicator inside files, missing
     response_kind).
  B) ``select_probes`` dispatches to the right class per response_kind
     (rce/ssti/path-traversal/xss/sqli + alias variants).
  C) Probe execution + verdict aggregation:
     - real-RCE-style fake lab → RceCanaryProbe passes → verdict=backend_probe.
     - echo-machine fake lab (always returns input) → all probes reject
       (canary never appears) → verdict=rejected.
     - unrecognised response_kind + legacy passed → fallback method
       ``llm_indicator_only``.

Exit code 0 = all green. Each section prints PASS/FAIL and the final
"OK" line is what CI/operators look for.
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from typing import Any

from app.services.sandbox import synthesizer_probes as probes
from app.services.sandbox.catalog import InjectionPoint
from app.services.sandbox.synthesizer import _validate_parsed


# ---------------------------------------------------------------------------
# Block A — _validate_parsed echo-trap rejections
# ---------------------------------------------------------------------------


_OK_PARSED = {
    "dockerfile": "FROM python:3.11-slim\nCOPY app.py /\nCMD python /app.py",
    "files": [{"path": "app.py", "content": "from flask import Flask, request"}],
    "container_port": 8080,
    "target_path": "/",
    "injection_point": {
        "name": "x",
        "method": "GET",
        "path": "/",
        "parameter": "q",
        "location": "query",
        "response_kind": "rce",
        "notes": "",
    },
    "payload_example": "; cat /etc/passwd",
    "success_indicator": "KESTREL_TOK_ABCDE12345",
}


def _section_a() -> bool:
    cases: list[tuple[str, dict, str]] = []

    short_ind = dict(_OK_PARSED, success_indicator="abc")
    cases.append(("short indicator rejected", short_ind, "너무 짧음"))

    eq_payload = dict(
        _OK_PARSED,
        payload_example="KESTREL_TOK_LONGENOUGH",
        success_indicator="KESTREL_TOK_LONGENOUGH",
    )
    cases.append(("indicator==payload rejected", eq_payload, "동일"))

    ind = "ECHO_TRAP_TOKEN_2026"
    in_files = dict(
        _OK_PARSED,
        files=[{"path": "app.py", "content": f"return '{ind}'"}],
        payload_example="; cat /etc/passwd",
        success_indicator=ind,
    )
    cases.append(("indicator-in-files rejected", in_files, "echo trap"))

    no_rk_ip = dict(_OK_PARSED["injection_point"], response_kind="")
    no_rk = dict(_OK_PARSED, injection_point=no_rk_ip)
    cases.append(("missing response_kind rejected", no_rk, "response_kind"))

    happy = _validate_parsed(_OK_PARSED)
    if happy is not None:
        print(f"  FAIL — clean parsed shape rejected: {happy}")
        return False
    print("  PASS — clean parsed shape accepted")

    all_ok = True
    for label, parsed, expect_substring in cases:
        err = _validate_parsed(parsed)
        if err is None:
            print(f"  FAIL — {label}: expected rejection containing '{expect_substring}', got accepted")
            all_ok = False
            continue
        if expect_substring not in err:
            print(f"  FAIL — {label}: rejection message did not mention '{expect_substring}': {err}")
            all_ok = False
            continue
        print(f"  PASS — {label}")
    return all_ok


# ---------------------------------------------------------------------------
# Block B — select_probes dispatch
# ---------------------------------------------------------------------------


def _section_b() -> bool:
    expected: dict[str, str] = {
        "rce": "rce_canary_read",
        "command-exec": "rce_canary_read",
        "command_exec": "rce_canary_read",
        "ssti": "ssti_arithmetic",
        "template-injection": "ssti_arithmetic",
        "path-traversal": "path_traversal_canary",
        "lfi": "path_traversal_canary",
        "xss": "xss_reflect_nonce",
        "html-reflect": "xss_reflect_nonce",
        "json-reflect": "xss_reflect_nonce",
        "sqli": "sqli_time_blind",
        "sql-injection": "sqli_time_blind",
    }
    all_ok = True
    for rk, expected_name in expected.items():
        chosen = probes.select_probes(rk)
        names = [p.name for p in chosen]
        if expected_name not in names:
            print(f"  FAIL — response_kind={rk!r}: expected {expected_name} in {names}")
            all_ok = False
        else:
            print(f"  PASS — {rk!r} → {expected_name}")
    unknown = probes.select_probes("totally-unknown-kind")
    if unknown:
        print(f"  FAIL — unknown response_kind matched probes: {[p.name for p in unknown]}")
        all_ok = False
    else:
        print("  PASS — unknown response_kind matched no probes")
    return all_ok


# ---------------------------------------------------------------------------
# Block C — fake-lab probe execution + verdict aggregation
# ---------------------------------------------------------------------------


@dataclass
class FakeHandle:
    container_name: str
    target_url: str = "http://lab.fake"


def _patch_proxy(reply_fn):
    """Replace ``probes.proxy_request`` with a callable returning the
    body that ``reply_fn(payload)`` produces. Returns the original so
    the caller can restore."""

    async def _fake(target_url, method, path, *, params=None, data=None, json=None, headers=None):
        bag = params or data or json or headers or {}
        payload = next(iter(bag.values())) if bag else ""
        return {"status_code": 200, "body": reply_fn(str(payload))}

    orig = probes.proxy_request
    probes.proxy_request = _fake  # type: ignore[assignment]
    return orig


def _patch_exec(stamps: dict[str, str]):
    """Replace ``probes.exec_in_lab`` with one that records canary writes
    into *stamps* (path → value) and returns exit_code=0. Returns the
    original so the caller can restore."""

    async def _fake(container_name, cmd, *, user=None, timeout_seconds=10.0):
        if len(cmd) >= 3 and cmd[0] == "sh" and cmd[1] == "-c":
            line = cmd[2]
            # Parse `printf %s 'value' > 'path'`
            try:
                value_start = line.index("printf %s ") + len("printf %s ")
                rest = line[value_start:]
                gt = rest.rindex(" > ")
                value_q = rest[:gt].strip()
                path_q = rest[gt + 3 :].strip()
                value = value_q.strip("'")
                path = path_q.strip("'")
                stamps[path] = value
            except ValueError:
                pass
        return 0, b""

    orig = probes.exec_in_lab
    probes.exec_in_lab = _fake  # type: ignore[assignment]
    return orig


async def _scenario_real_rce() -> tuple[bool, probes.VerificationVerdict]:
    """Fake lab that, for shell-injection payloads, opens the canary file
    and returns its contents — what a real RCE lab would do."""
    stamps: dict[str, str] = {}
    orig_exec = _patch_exec(stamps)
    try:
        def reply(payload: str) -> str:
            for path, value in stamps.items():
                # Any payload that includes 'cat <path>' triggers the read.
                if path in payload:
                    return f"output: {value}"
            return "(no output)"
        orig_proxy = _patch_proxy(reply)
        try:
            ip = InjectionPoint(
                name="x", method="GET", path="/", parameter="q",
                location="query", response_kind="rce", notes="",
            )
            handle = FakeHandle(container_name="lab1")
            results = []
            for probe in probes.select_probes("rce"):
                results.append(await probe.run(handle=handle, ip=ip))
            verdict = probes.build_verdict("rce", results, fallback_passed=False)
            return verdict.passed and verdict.method == "backend_probe", verdict
        finally:
            probes.proxy_request = orig_proxy  # type: ignore[assignment]
    finally:
        probes.exec_in_lab = orig_exec  # type: ignore[assignment]


async def _scenario_echo_machine() -> tuple[bool, probes.VerificationVerdict]:
    """Lab returns the payload verbatim regardless of canary — the classic
    echo machine our probes must reject."""
    stamps: dict[str, str] = {}
    orig_exec = _patch_exec(stamps)
    try:
        def reply(payload: str) -> str:
            return f"you said: {payload}"
        orig_proxy = _patch_proxy(reply)
        try:
            ip = InjectionPoint(
                name="x", method="GET", path="/", parameter="q",
                location="query", response_kind="rce", notes="",
            )
            handle = FakeHandle(container_name="lab2")
            results = []
            for probe in probes.select_probes("rce"):
                results.append(await probe.run(handle=handle, ip=ip))
            verdict = probes.build_verdict("rce", results, fallback_passed=True)
            return (not verdict.passed) and verdict.method == "rejected", verdict
        finally:
            probes.proxy_request = orig_proxy  # type: ignore[assignment]
    finally:
        probes.exec_in_lab = orig_exec  # type: ignore[assignment]


async def _scenario_unknown_kind_fallback() -> tuple[bool, probes.VerificationVerdict]:
    """No probe applies — verdict must fall back to llm_indicator_only."""
    verdict = probes.build_verdict("totally-novel-kind", [], fallback_passed=True)
    return verdict.passed and verdict.method == "llm_indicator_only", verdict


def _section_c() -> bool:
    async def _run() -> bool:
        ok = True
        passed, v = await _scenario_real_rce()
        print(f"  {'PASS' if passed else 'FAIL'} — real-RCE fake lab → method={v.method} reason={v.rejection_reason}")
        ok = ok and passed

        passed, v = await _scenario_echo_machine()
        print(f"  {'PASS' if passed else 'FAIL'} — echo-machine fake lab → method={v.method}")
        if not passed:
            for r in v.probe_results:
                print(f"      probe[{r.name}] passed={r.passed} :: {r.rationale[:120]}")
        ok = ok and passed

        passed, v = await _scenario_unknown_kind_fallback()
        print(f"  {'PASS' if passed else 'FAIL'} — unknown response_kind → method={v.method}")
        ok = ok and passed
        return ok

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> int:
    print("[A] _validate_parsed echo-trap gates")
    a = _section_a()
    print("[B] select_probes dispatch")
    b = _section_b()
    print("[C] backend probe execution + verdict aggregation")
    c = _section_c()
    if a and b and c:
        print("OK — PR 9-L smoke green")
        return 0
    print("FAIL — at least one PR 9-L smoke section failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())

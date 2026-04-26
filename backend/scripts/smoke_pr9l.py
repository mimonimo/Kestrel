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
        "xxe": "xxe_canary_read",
        "xml-external-entity": "xxe_canary_read",
        "open-redirect": "open_redirect_nonce",
        "url-redirect": "open_redirect_nonce",
        "deserialization": "deser_pickle_canary_write",
        "pickle": "deser_pickle_canary_write",
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
    """Replace ``probes.proxy_request`` with a callable returning what
    ``reply_fn(payload)`` produces.

    ``reply_fn`` may return either a string (treated as body, no headers)
    or a dict with explicit ``body``, ``status_code``, and
    ``response_headers`` keys — the latter form is what redirect-style
    fakes use.
    """

    async def _fake(target_url, method, path, *, params=None, data=None, json=None, headers=None):
        bag = params or data or json or headers or {}
        payload = next(iter(bag.values())) if bag else ""
        out = reply_fn(str(payload))
        if isinstance(out, dict):
            return {
                "status_code": int(out.get("status_code", 200)),
                "body": str(out.get("body", "")),
                "response_headers": dict(out.get("response_headers") or {}),
            }
        return {"status_code": 200, "body": str(out), "response_headers": {}}

    orig = probes.proxy_request
    probes.proxy_request = _fake  # type: ignore[assignment]
    return orig


def _patch_exec(stamps: dict[str, str]):
    """Replace ``probes.exec_in_lab`` with a small in-memory shell that
    handles the three command shapes our probes actually issue:

      * ``printf %s 'value' > 'path'`` → stamps[path] = value
      * ``test ! -e 'path'`` → exit 0 if path absent, 1 if present
      * ``cat 'path' …`` → stdout = stamps.get(path, "")

    Anything else returns exit 0 with empty output. Returns the original
    so callers can restore it.
    """

    async def _fake(container_name, cmd, *, user=None, timeout_seconds=10.0):
        if len(cmd) >= 3 and cmd[0] == "sh" and cmd[1] == "-c":
            line = cmd[2].strip()
            if "printf %s " in line and " > " in line:
                try:
                    value_start = line.index("printf %s ") + len("printf %s ")
                    rest = line[value_start:]
                    gt = rest.rindex(" > ")
                    value = rest[:gt].strip().strip("'")
                    path = rest[gt + 3 :].strip().strip("'")
                    stamps[path] = value
                except ValueError:
                    pass
                return 0, b""
            if line.startswith("test ! -e "):
                path = line[len("test ! -e ") :].strip().strip("'")
                return (0 if path not in stamps else 1), b""
            if line.startswith("cat "):
                rest = line[len("cat ") :].strip()
                path = rest.split(" ", 1)[0].strip().strip("'")
                if path in stamps:
                    return 0, stamps[path].encode()
                return 1, b""
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


async def _scenario_real_xxe() -> tuple[bool, probes.VerificationVerdict]:
    """Lab parses XML and inlines `file://` SYSTEM entity contents into
    the response — i.e., a real XXE-vulnerable parser."""
    import re as _re
    stamps: dict[str, str] = {}
    orig_exec = _patch_exec(stamps)
    try:
        file_re = _re.compile(r'SYSTEM\s+"file://([^"]+)"')

        def reply(payload: str) -> str:
            m = file_re.search(payload)
            if m and m.group(1) in stamps:
                return f"<r>{stamps[m.group(1)]}</r>"
            return "<r>nothing</r>"

        orig_proxy = _patch_proxy(reply)
        try:
            ip = InjectionPoint(
                name="x", method="POST", path="/", parameter="xml",
                location="form", response_kind="xxe", notes="",
            )
            handle = FakeHandle(container_name="lab_xxe")
            results = []
            for probe in probes.select_probes("xxe"):
                results.append(await probe.run(handle=handle, ip=ip))
            verdict = probes.build_verdict("xxe", results, fallback_passed=False)
            return verdict.passed and verdict.method == "backend_probe", verdict
        finally:
            probes.proxy_request = orig_proxy  # type: ignore[assignment]
    finally:
        probes.exec_in_lab = orig_exec  # type: ignore[assignment]


async def _scenario_real_open_redirect() -> tuple[bool, probes.VerificationVerdict]:
    """Lab returns 302 with the user-supplied URL in the Location header."""
    def reply(payload: str) -> dict[str, Any]:
        return {
            "status_code": 302,
            "body": "",
            "response_headers": {"Location": payload},
        }
    orig_proxy = _patch_proxy(reply)
    try:
        ip = InjectionPoint(
            name="r", method="GET", path="/redirect", parameter="next",
            location="query", response_kind="open-redirect", notes="",
        )
        handle = FakeHandle(container_name="lab_redir")
        results = []
        for probe in probes.select_probes("open-redirect"):
            results.append(await probe.run(handle=handle, ip=ip))
        verdict = probes.build_verdict("open-redirect", results, fallback_passed=False)
        return verdict.passed and verdict.method == "backend_probe", verdict
    finally:
        probes.proxy_request = orig_proxy  # type: ignore[assignment]


async def _scenario_hardcoded_redirect() -> tuple[bool, probes.VerificationVerdict]:
    """Lab redirects to a hardcoded URL regardless of input — must be
    rejected (3xx but Location does not include backend nonce)."""
    def reply(payload: str) -> dict[str, Any]:
        return {
            "status_code": 302,
            "body": "",
            "response_headers": {"Location": "https://always-the-same.example/"},
        }
    orig_proxy = _patch_proxy(reply)
    try:
        ip = InjectionPoint(
            name="r", method="GET", path="/redirect", parameter="next",
            location="query", response_kind="open-redirect", notes="",
        )
        handle = FakeHandle(container_name="lab_redir_fake")
        results = []
        for probe in probes.select_probes("open-redirect"):
            results.append(await probe.run(handle=handle, ip=ip))
        verdict = probes.build_verdict("open-redirect", results, fallback_passed=True)
        return (not verdict.passed) and verdict.method == "rejected", verdict
    finally:
        probes.proxy_request = orig_proxy  # type: ignore[assignment]


async def _scenario_real_deserialization() -> tuple[bool, probes.VerificationVerdict]:
    """Lab base64-decodes the parameter and calls `pickle.loads()` on
    it — running the gadget's `__reduce__` → `os.system`, which (in a
    real container) writes the canary file. We don't want to actually
    spawn a real shell on the test runner, so we monkey-patch
    ``os.system`` for the duration of the unpickle call: the patched
    version captures the command, parses out the canary path/value,
    and stamps our in-memory exec mock — exactly the visible side
    effect a real Python lab would produce."""
    import base64 as _b64
    import os as _os
    import pickle as _pickle
    stamps: dict[str, str] = {}
    orig_exec = _patch_exec(stamps)
    try:
        def _stamp_from_cmd(cmd: str) -> None:
            # Mirrors the parser in _patch_exec — handles both
            # ``printf %s value > path`` (shlex.quote skipped because the
            # token has no shell metacharacters) and the quoted variant.
            line = cmd.strip()
            if "printf %s " not in line or " > " not in line:
                return
            try:
                value_start = line.index("printf %s ") + len("printf %s ")
                rest = line[value_start:]
                gt = rest.rindex(" > ")
                value = rest[:gt].strip().strip("'")
                path = rest[gt + 3 :].strip().strip("'")
            except ValueError:
                return
            stamps[path] = value

        def reply(payload: str) -> str:
            try:
                raw = _b64.b64decode(payload)
            except Exception:
                return "decode failed"
            # Pickle resolves `os.system` to its real underlying module
            # at unpickle time (`posix.system` on Unix, `nt.system` on
            # Windows), not via the `os` re-export — patch both spots so
            # the gadget's call lands on our fake regardless.
            import sys as _sys
            real_system = _os.system
            underlying_mod = _sys.modules.get(_os.name) or _os
            real_underlying = getattr(underlying_mod, "system", real_system)
            captured: list[str] = []

            def fake_system(cmd):  # signature mirrors os.system
                captured.append(str(cmd))
                return 0

            _os.system = fake_system  # type: ignore[assignment]
            if underlying_mod is not _os:
                underlying_mod.system = fake_system  # type: ignore[attr-defined]
            try:
                _pickle.loads(raw)  # noqa: S301 — intentional in-test gadget exec
            except Exception:
                pass
            finally:
                _os.system = real_system  # type: ignore[assignment]
                if underlying_mod is not _os:
                    underlying_mod.system = real_underlying  # type: ignore[attr-defined]
            for cmd in captured:
                _stamp_from_cmd(cmd)
            return "ok"

        orig_proxy = _patch_proxy(reply)
        try:
            ip = InjectionPoint(
                name="d", method="POST", path="/", parameter="blob",
                location="form", response_kind="deserialization", notes="",
            )
            handle = FakeHandle(container_name="lab_deser")
            results = []
            for probe in probes.select_probes("deserialization"):
                results.append(await probe.run(handle=handle, ip=ip))
            verdict = probes.build_verdict("deserialization", results, fallback_passed=False)
            return verdict.passed and verdict.method == "backend_probe", verdict
        finally:
            probes.proxy_request = orig_proxy  # type: ignore[assignment]
    finally:
        probes.exec_in_lab = orig_exec  # type: ignore[assignment]


async def _scenario_inert_deserialization() -> tuple[bool, probes.VerificationVerdict]:
    """Lab takes the param, returns it (or anything), but doesn't actually
    call pickle.loads — canary file never appears, must be rejected."""
    stamps: dict[str, str] = {}
    orig_exec = _patch_exec(stamps)
    try:
        def reply(payload: str) -> str:
            return f"received {len(payload)} bytes"
        orig_proxy = _patch_proxy(reply)
        try:
            ip = InjectionPoint(
                name="d", method="POST", path="/", parameter="blob",
                location="form", response_kind="deserialization", notes="",
            )
            handle = FakeHandle(container_name="lab_deser_inert")
            results = []
            for probe in probes.select_probes("deserialization"):
                results.append(await probe.run(handle=handle, ip=ip))
            verdict = probes.build_verdict("deserialization", results, fallback_passed=True)
            return (not verdict.passed) and verdict.method == "rejected", verdict
        finally:
            probes.proxy_request = orig_proxy  # type: ignore[assignment]
    finally:
        probes.exec_in_lab = orig_exec  # type: ignore[assignment]


def _section_c() -> bool:
    async def _run() -> bool:
        ok = True
        scenarios = [
            ("real-RCE fake lab", _scenario_real_rce),
            ("echo-machine fake lab", _scenario_echo_machine),
            ("unknown response_kind fallback", _scenario_unknown_kind_fallback),
            ("real-XXE fake lab", _scenario_real_xxe),
            ("real open-redirect fake lab", _scenario_real_open_redirect),
            ("hardcoded redirect (rejected)", _scenario_hardcoded_redirect),
            ("real-deserialization fake lab", _scenario_real_deserialization),
            ("inert deserialization (rejected)", _scenario_inert_deserialization),
        ]
        for label, scen in scenarios:
            passed, v = await scen()
            print(f"  {'PASS' if passed else 'FAIL'} — {label} → method={v.method}"
                  + (f" reason={v.rejection_reason}" if v.rejection_reason else ""))
            if not passed:
                for r in v.probe_results:
                    print(f"      probe[{r.name}] passed={r.passed} :: {r.rationale[:160]}")
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

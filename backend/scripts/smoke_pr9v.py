"""PR 9-V smoke — auth-bypass differential probe.

Pure-python: monkey-patch ``proxy_request`` so we can shape the lab's
behavior per request without docker. Five scenarios:

  A) alias dispatch: every applicable response_kind picks the probe.
  B) real auth-bypass lab — anonymous→401, random→401, "admin"→200 with
     a bigger body. Probe must accept.
  C) echo trap — same body for every input, status always 200. Probe
     must reject ("anonymous + random 모두 unauthorized shape 가 아님"
     OR "anonymous 와 거의 동일").
  D) "always 200 with same body" — same as C but with payload echoed in
     body. Differential is trivial. Probe must reject (no real gate).
  E) "any input bypasses" — anonymous returns 401; ANY non-empty value
     returns 200 + protected body. Random control passes too → reject.

Exit 0 = all green.
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass

from app.services.sandbox import synthesizer_probes as probes
from app.services.sandbox.catalog import InjectionPoint


@dataclass
class FakeHandle:
    container_name: str = "lab.fake"
    target_url: str = "http://lab.fake"


def _section_a() -> bool:
    aliases = [
        "auth-bypass", "broken-auth", "missing-auth", "broken-access-control",
        "idor", "auth-skip", "authentication-bypass",
    ]
    all_ok = True
    for rk in aliases:
        chosen = probes.select_probes(rk)
        names = [p.name for p in chosen]
        if "auth_bypass_differential" not in names:
            print(f"  FAIL — {rk!r} → {names}")
            all_ok = False
        else:
            print(f"  PASS — {rk!r} → auth_bypass_differential")
    return all_ok


def _patch_proxy(behavior):
    async def _fake(target_url, method, path, *, params=None, data=None, json=None, headers=None):
        bag = params or data or json or headers or {}
        payload = str(next(iter(bag.values())) if bag else "")
        out = behavior(payload)
        return {
            "status_code": int(out.get("status_code", 200)),
            "body": str(out.get("body", "")),
            "response_headers": dict(out.get("response_headers") or {}),
        }
    orig = probes.proxy_request
    probes.proxy_request = _fake  # type: ignore[assignment]
    return orig


async def _run(behavior) -> probes.ProbeOutcome:
    orig = _patch_proxy(behavior)
    try:
        ip = InjectionPoint(
            name="role", method="GET", path="/admin",
            parameter="role", location="query",
            response_kind="auth-bypass", notes="",
        )
        probe = probes.AuthBypassDifferentialProbe()
        return await probe.run(handle=FakeHandle(), ip=ip)
    finally:
        probes.proxy_request = orig  # type: ignore[assignment]


# B — real auth-bypass: anonymous + random get 401, "admin" gets the
# protected page (much longer body).
def _real_auth(payload: str):
    if payload == "admin":
        return {
            "status_code": 200,
            "body": "<h1>Admin Dashboard</h1>" + "<p>secret</p>" * 40,  # ~520 bytes
        }
    return {"status_code": 401, "body": "Unauthorized"}


# C — echo trap: same short echo for every input, always 200.
def _echo_trap(payload: str):
    return {"status_code": 200, "body": f"input was: {payload}"}


# D — "always 200 with same fixed body" — no variance at all.
def _always_200_fixed(payload: str):
    return {"status_code": 200, "body": "<h1>Welcome</h1>"}


# E — "any input bypasses": anonymous → 401, any non-empty value →
# protected page (random control also gets it). Should reject.
def _any_input_bypass(payload: str):
    if not payload:
        return {"status_code": 401, "body": "Unauthorized"}
    return {
        "status_code": 200,
        "body": "<h1>Admin Dashboard</h1>" + "<p>secret</p>" * 40,
    }


async def main() -> int:
    print("[A] alias dispatch")
    a = _section_a()

    print("\n[B] real auth-bypass lab — probe should accept")
    out = await _run(_real_auth)
    b = out.passed
    print(f"  {'PASS' if b else 'FAIL'} — passed={out.passed} rationale={out.rationale[:140]}")

    print("\n[C] echo trap (always 200, body echoes input) — probe should reject")
    out = await _run(_echo_trap)
    # Reject because "anonymous + random unauthorized shape 아님" → no gate.
    c = (not out.passed) and (
        "인증 게이트 자체가 없" in out.rationale
        or "anonymous + random" in out.rationale
    )
    print(f"  {'PASS' if c else 'FAIL'} — passed={out.passed} rationale={out.rationale[:140]}")

    print("\n[D] always-200-same-body — probe should reject (no differential)")
    out = await _run(_always_200_fixed)
    d = (not out.passed)
    print(f"  {'PASS' if d else 'FAIL'} — passed={out.passed} rationale={out.rationale[:140]}")

    print("\n[E] any-input-bypasses — probe should reject (random control bypasses too)")
    out = await _run(_any_input_bypass)
    e = (not out.passed) and (
        "본문 차이를 만들지 못함" in out.rationale
        or "사실상 없는" in out.rationale
        or "거의 동일" in out.rationale
        or "anonymous + random" in out.rationale
    )
    print(f"  {'PASS' if e else 'FAIL'} — passed={out.passed} rationale={out.rationale[:140]}")

    ok = a and b and c and d and e
    print(f"\n{'OK' if ok else 'FAIL'} — PR 9-V smoke {'green' if ok else 'red'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

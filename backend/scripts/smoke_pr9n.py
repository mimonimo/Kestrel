"""PR 9-N smoke — SSRF backend probe + dispatch + verdict aggregation.

Pure-python: monkey-patches ``_ssrf_canary``, ``proxy_request``, and
``exec_in_lab`` so we exercise the SsrfCanaryProbe end-to-end without
docker.

Three blocks:
  A) ``select_probes`` dispatches every SSRF alias to SsrfCanaryProbe.
  B) Real-SSRF fake lab — payload is a URL; the lab "fetches" it by
     writing a hit line to the in-memory canary log only when the URL
     points at the canary host. Probe must pass with method=backend_probe.
  C) Echo-trap fake lab — lab returns 200 with payload echoed in body
     but never touches the canary. Probe must reject with rationale that
     mentions "토큰이 없음".
  D) Pathological "always pings canary" fake lab — writes to canary log
     even on the negative-control payload. Probe must reject with
     rationale that mentions "음성 대조" / "무조건 호출".

Exit code 0 = all green.
"""
from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass

from app.services.sandbox import synthesizer_probes as probes
from app.services.sandbox.catalog import InjectionPoint


@dataclass
class FakeHandle:
    container_name: str
    target_url: str = "http://lab.fake"


# ---------------------------------------------------------------------------
# Block A — alias dispatch
# ---------------------------------------------------------------------------


def _section_a() -> bool:
    aliases = [
        "ssrf",
        "server-side-request-forgery",
        "url-fetch",
        "remote-fetch",
        "url-include",
        "outbound-fetch",
    ]
    all_ok = True
    for rk in aliases:
        chosen = probes.select_probes(rk)
        names = [p.name for p in chosen]
        if "ssrf_inbound_canary" not in names:
            print(f"  FAIL — {rk!r} → {names} (missing ssrf_inbound_canary)")
            all_ok = False
        else:
            print(f"  PASS — {rk!r} → ssrf_inbound_canary")
    return all_ok


# ---------------------------------------------------------------------------
# Patch helpers shared across scenarios
# ---------------------------------------------------------------------------


# Per-scenario state. The fake `exec_in_lab` reads from this; the fake
# `proxy_request` mutates it based on the lab's behavior. Reset each
# scenario so tokens/canary names don't leak between them.
_state: dict = {}


def _fake_canary_name() -> str:
    return "kestrel-ssrf-canary-FAKE"


@asynccontextmanager
async def _fake_canary():
    name = _fake_canary_name()
    _state["canary_name"] = name
    _state.setdefault("hits", [])
    yield name


def _patch_canary():
    orig = probes._ssrf_canary
    probes._ssrf_canary = _fake_canary  # type: ignore[assignment]
    return orig


def _patch_exec_for_canary():
    """``exec_in_lab(canary_name, ['sh', '-c', 'cat /tmp/hits.log...'])``
    returns the in-memory log; anything else returns empty."""

    async def _fake(container_name, cmd, *, user=None, timeout_seconds=10.0):
        if (
            container_name == _state.get("canary_name")
            and len(cmd) >= 3
            and cmd[0] == "sh"
            and "hits.log" in cmd[2]
        ):
            log_str = "\n".join(_state.get("hits", []))
            return 0, log_str.encode()
        return 0, b""

    orig = probes.exec_in_lab
    probes.exec_in_lab = _fake  # type: ignore[assignment]
    return orig


def _patch_proxy(behavior):
    """``behavior(payload) -> dict | None``. dict = response. None = no
    response side-effect (still returns a default 200 OK body). The
    behavior callback is also where the lab "fetches" the URL — it can
    append to ``_state['hits']`` to simulate a real outbound call."""

    async def _fake(target_url, method, path, *, params=None, data=None, json=None, headers=None):
        bag = params or data or json or headers or {}
        payload = str(next(iter(bag.values())) if bag else "")
        out = behavior(payload)
        if out is None:
            return {"status_code": 200, "body": "", "response_headers": {}}
        return {
            "status_code": int(out.get("status_code", 200)),
            "body": str(out.get("body", "")),
            "response_headers": dict(out.get("response_headers") or {}),
        }

    orig = probes.proxy_request
    probes.proxy_request = _fake  # type: ignore[assignment]
    return orig


def _restore(orig_canary, orig_exec, orig_proxy):
    probes._ssrf_canary = orig_canary  # type: ignore[assignment]
    probes.exec_in_lab = orig_exec  # type: ignore[assignment]
    probes.proxy_request = orig_proxy  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Block B — real-SSRF fake lab
# ---------------------------------------------------------------------------


def _real_ssrf_behavior(payload: str):
    """Lab that genuinely fetches whatever URL it's handed — but only
    writes to its outbound buffer if the URL host resolves on its
    network. We approximate that by checking the payload contains the
    canary's hostname."""
    canary = _state.get("canary_name", "")
    if canary and canary in payload:
        # Extract the path component (after the host) for the hit log.
        # Quick-and-dirty: drop the "http://<host>" prefix.
        prefix = f"http://{canary}"
        if payload.startswith(prefix):
            path = payload[len(prefix):] or "/"
            _state["hits"].append(f"2026-01-01T00:00:00 {path}")
    return {"status_code": 200, "body": f"fetched {payload[:30]}"}


async def _scenario_real_ssrf() -> tuple[bool, probes.ProbeOutcome]:
    _state.clear()
    orig_c = _patch_canary()
    orig_e = _patch_exec_for_canary()
    orig_p = _patch_proxy(_real_ssrf_behavior)
    try:
        ip = InjectionPoint(
            name="url",
            method="GET",
            path="/fetch",
            parameter="target",
            location="query",
            response_kind="ssrf",
            notes="",
        )
        probe = probes.SsrfCanaryProbe()
        outcome = await probe.run(handle=FakeHandle(container_name="lab.fake"), ip=ip)
        return outcome.passed, outcome
    finally:
        _restore(orig_c, orig_e, orig_p)


# ---------------------------------------------------------------------------
# Block C — echo-trap fake lab (no SSRF)
# ---------------------------------------------------------------------------


def _echo_trap_behavior(payload: str):
    # Reflects payload but never touches the canary log.
    return {"status_code": 200, "body": f"you sent: {payload}"}


async def _scenario_echo_trap() -> tuple[bool, probes.ProbeOutcome]:
    _state.clear()
    orig_c = _patch_canary()
    orig_e = _patch_exec_for_canary()
    orig_p = _patch_proxy(_echo_trap_behavior)
    try:
        ip = InjectionPoint(
            name="url",
            method="GET",
            path="/fetch",
            parameter="target",
            location="query",
            response_kind="ssrf",
            notes="",
        )
        probe = probes.SsrfCanaryProbe()
        outcome = await probe.run(handle=FakeHandle(container_name="lab.fake"), ip=ip)
        # Echo trap should be REJECTED.
        return (not outcome.passed) and ("토큰이 없음" in outcome.rationale), outcome
    finally:
        _restore(orig_c, orig_e, orig_p)


# ---------------------------------------------------------------------------
# Block D — pathological "always pings canary" lab
# ---------------------------------------------------------------------------


def _always_pings_behavior(payload: str):
    """Lab that ignores the URL parameter and ALWAYS hits the canary
    with some hardcoded path. Real SSRF would only hit when the URL
    actually points at the canary; this one hits no matter what."""
    # We need the negative-control hit to mention SOMETHING — but per
    # SsrfCanaryProbe rejection logic we trigger when EITHER the
    # positive token OR the negative token appears in the negative log.
    # So the lab writes a fixed entry containing the negative token to
    # simulate "the URL was used as-is, even though it points to a non-
    # existent host". A more realistic pathology — lab pings canary on
    # any input — also gets caught by the same check.
    canary = _state.get("canary_name", "")
    # Just record any inbound payload. The probe sees both pos+neg tokens
    # in the log and rejects.
    if "ssrf_neg" in payload:
        _state["hits"].append(f"2026-01-01T00:00:00 /{payload.rsplit('/', 1)[-1]}")
    elif "ssrf_pos" in payload and canary:
        _state["hits"].append(f"2026-01-01T00:00:00 /{payload.rsplit('/', 1)[-1]}")
    return {"status_code": 200, "body": "ok"}


async def _scenario_always_pings() -> tuple[bool, probes.ProbeOutcome]:
    _state.clear()
    orig_c = _patch_canary()
    orig_e = _patch_exec_for_canary()
    orig_p = _patch_proxy(_always_pings_behavior)
    try:
        ip = InjectionPoint(
            name="url",
            method="GET",
            path="/fetch",
            parameter="target",
            location="query",
            response_kind="ssrf",
            notes="",
        )
        probe = probes.SsrfCanaryProbe()
        outcome = await probe.run(handle=FakeHandle(container_name="lab.fake"), ip=ip)
        # Should reject because negative control produced a hit.
        return (
            (not outcome.passed)
            and ("음성 대조" in outcome.rationale or "무조건" in outcome.rationale)
        ), outcome
    finally:
        _restore(orig_c, orig_e, orig_p)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def main() -> int:
    print("[A] select_probes — SSRF aliases dispatch to SsrfCanaryProbe")
    a_ok = _section_a()

    print("\n[B] real-SSRF fake lab — probe should accept (backend_probe)")
    b_ok, b_out = await _scenario_real_ssrf()
    print(f"  {'PASS' if b_ok else 'FAIL'} — passed={b_out.passed} rationale={b_out.rationale[:120]}")

    print("\n[C] echo-trap lab — probe should reject (no canary hit)")
    c_ok, c_out = await _scenario_echo_trap()
    print(f"  {'PASS' if c_ok else 'FAIL'} — passed={c_out.passed} rationale={c_out.rationale[:120]}")

    print("\n[D] always-pings-canary lab — probe should reject (negative hit)")
    d_ok, d_out = await _scenario_always_pings()
    print(f"  {'PASS' if d_ok else 'FAIL'} — passed={d_out.passed} rationale={d_out.rationale[:120]}")

    all_ok = a_ok and b_ok and c_ok and d_ok
    print(f"\n{'OK' if all_ok else 'FAIL'} — PR 9-N smoke {'green' if all_ok else 'red'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

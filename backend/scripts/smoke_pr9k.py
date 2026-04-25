"""PR 9-K smoke test — cached_hit bypass + prior-attempt prompt injection.

Three scenarios, all gated on inspecting the prompt actually handed to the LLM:

  A) verified+degraded existing  → cached_hit BYPASSED, prior block injected
  B) demoted (verified=False, no recent attempt) existing → cooldown skipped,
     LLM called with prior block (the demote-not-delete GC change is what
     keeps this row alive across opportunistic GC sweeps).
  C) None existing → empty prior block, LLM called with original prompt
     (no "이전 시도" marker).

Uses ``alpine:latest`` (real local image) for the seeded mapping so the
opportunistic GC inside ``synthesize()`` doesn't trip the image_missing
demote pass mid-test and corrupt the fixture.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

from sqlalchemy import delete, select

from app.core.database import SessionLocal as async_session_factory
from app.models import (
    CveLabFeedback,
    CveLabMapping,
    LabSourceKind,
    Source,
    Vulnerability,
)
from app.services.sandbox import synthesizer as syn_mod


CVE_A = "CVE-2099-PR9K-A"
CVE_B = "CVE-2099-PR9K-B"
CVE_C = "CVE-2099-PR9K-C"


_CAPTURED: dict[str, list[str]] = {}


def _make_fake_call_llm(label: str):
    """Capture the rendered user prompt and return a deliberately malformed
    JSON so synthesize() exits via the schema-validation path on the first
    attempt — no real tokens, no docker build, no verify cycle.
    """

    async def _fake(db, system, user_prompt, *, force_json=False):
        _CAPTURED.setdefault(label, []).append(user_prompt)
        return '{"intentionally": "malformed for smoke — missing required keys"}'

    return _fake


async def _seed(db, cve_id: str, *, verified: bool, degraded: bool, with_feedback: bool):
    """Insert a vulnerability + a synthesized mapping in the requested state."""
    await db.execute(delete(CveLabFeedback).where(
        CveLabFeedback.mapping_id.in_(
            select(CveLabMapping.id).where(CveLabMapping.cve_id == cve_id)
        )
    ))
    await db.execute(delete(CveLabMapping).where(CveLabMapping.cve_id == cve_id))
    await db.execute(delete(Vulnerability).where(Vulnerability.cve_id == cve_id))

    vuln = Vulnerability(
        cve_id=cve_id,
        title=f"PR9K smoke {cve_id}",
        description="자동 테스트용 — 실제 CVE 아님.",
        source=Source.NVD,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )
    db.add(vuln)
    await db.flush()

    mapping = CveLabMapping(
        cve_id=cve_id,
        kind=LabSourceKind.SYNTHESIZED,
        lab_kind=f"synthesized/{cve_id}/seed",
        spec={
            "run_kind": "image",
            "image": "alpine:latest",
            "container_port": 8080,
            "target_path": "/",
            "injection_points": [
                {
                    "name": "echo",
                    "method": "GET",
                    "path": "/echo",
                    "parameter": "msg",
                    "location": "query",
                    "response_kind": "html-reflect",
                    "notes": "seed",
                }
            ],
            "success_indicator": "SYN_OK_SEED",
        },
        known_good_payload={
            "method": "GET",
            "path": "/echo",
            "parameter": "msg",
            "location": "query",
            "payload": "<script>alert('SYN_OK_SEED')</script>",
            "success_indicator": "SYN_OK_SEED",
        },
        verified=verified,
        feedback_up=1 if degraded else 0,
        feedback_down=4 if degraded else 0,
        notes="seed for PR9K smoke",
    )
    db.add(mapping)
    await db.flush()

    if with_feedback:
        db.add(CveLabFeedback(
            mapping_id=mapping.id,
            client_id="smoke-client",
            vote="down",
            note="indicator는 보이지만 실제 SSTI가 아니라 단순 reflect로 보입니다.",
        ))
        await db.flush()

    await db.commit()
    return vuln, mapping


async def _seed_no_mapping(db, cve_id: str):
    await db.execute(delete(Vulnerability).where(Vulnerability.cve_id == cve_id))
    vuln = Vulnerability(
        cve_id=cve_id,
        title=f"PR9K smoke {cve_id}",
        description="자동 테스트용 — 실제 CVE 아님.",
        source=Source.NVD,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )
    db.add(vuln)
    await db.commit()
    return vuln


async def _cleanup(db, cve_ids: list[str]):
    for cve_id in cve_ids:
        await db.execute(delete(CveLabFeedback).where(
            CveLabFeedback.mapping_id.in_(
                select(CveLabMapping.id).where(CveLabMapping.cve_id == cve_id)
            )
        ))
        await db.execute(delete(CveLabMapping).where(CveLabMapping.cve_id == cve_id))
        await db.execute(delete(Vulnerability).where(Vulnerability.cve_id == cve_id))
    await db.commit()


async def _run_one(label: str, cve_id: str, expect_prior: bool, expect_phase_seen: list[str]):
    seen_phases: list[str] = []

    async def progress(phase, message, payload):
        seen_phases.append(phase)

    syn_mod.call_llm = _make_fake_call_llm(label)  # type: ignore[assignment]

    async with async_session_factory() as db:
        vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
        assert vuln is not None, f"missing seeded vuln for {cve_id}"

        await syn_mod.synthesize(db, vuln, progress=progress)

        captured = _CAPTURED.get(label, [])
        if not captured:
            print(f"[{label}] FAIL — synthesize() returned without calling LLM. phases={seen_phases}")
            return False

        prompt = captured[0]
        has_prior = "이전 시도" in prompt
        ok_prior = (has_prior == expect_prior)
        ok_phases = all(p in seen_phases for p in expect_phase_seen)

        marker = "OK" if (ok_prior and ok_phases) else "FAIL"
        print(f"[{label}] {marker}")
        print(f"  prompt has '이전 시도': {has_prior} (expected {expect_prior})")
        print(f"  phases seen: {seen_phases}")
        if has_prior:
            # Surface the injected block for visual sanity.
            start = prompt.find("## 이전 시도")
            end = prompt.find("## 출력 형식", start)
            block = prompt[start:end].strip()
            print("  --- injected block ---")
            for line in block.splitlines():
                print(f"  | {line}")
            print("  ---------------------")
        return ok_prior and ok_phases


async def main():
    async with async_session_factory() as db:
        # Scenario A — verified+degraded
        await _seed(db, CVE_A, verified=True, degraded=True, with_feedback=True)
        # Scenario B — demoted (verified=False) row, no recent attempt
        await _seed(db, CVE_B, verified=False, degraded=False, with_feedback=True)
        # Scenario C — no existing mapping at all (only the vuln row)
        await _seed_no_mapping(db, CVE_C)

    results = []
    results.append(await _run_one(
        "A degraded+verified",
        CVE_A,
        expect_prior=True,
        expect_phase_seen=["start", "call_llm"],
    ))
    results.append(await _run_one(
        "B demoted (image_missing fallout)",
        CVE_B,
        expect_prior=True,
        expect_phase_seen=["start", "call_llm"],
    ))
    results.append(await _run_one(
        "C fresh CVE",
        CVE_C,
        expect_prior=False,
        expect_phase_seen=["start", "call_llm"],
    ))

    async with async_session_factory() as db:
        await _cleanup(db, [CVE_A, CVE_B, CVE_C])

    if all(results):
        print("\nALL SMOKE PASSED")
        sys.exit(0)
    print("\nSOME SMOKE FAILED")
    sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

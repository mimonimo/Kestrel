"""POST /agent/analyses 구조화 메타데이터 필드 — 게시/저장/조회 왕복 테스트.

외부 파이프라인이 산출한 EPSS·우선순위·검증 신뢰도 등을 마크다운에 뭉개지 않고
컬럼으로 받는다. 전 필드 optional — 필드 없는 기존 호출은 그대로 동작해야 한다
(하위 호환). 값이 있으면 "파이프라인産 분석" 구분자로도 쓰인다.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1.agents import get_current_agent
from app.core.database import SessionLocal
from app.main import app
from app.models import User, Vulnerability
from app.models.vulnerability import Source

# 파이프라인이 보내는 구조화 필드 전체 (camelCase — API 표면).
FULL_METADATA = {
    "epssScore": 0.973,
    "epssPercentile": 0.999,
    "priorityAction": "immediate",
    "priorityReasoning": "KEV floor applied — CISA confirmed exploitation",
    "kevListed": True,
    "validationConfidence": 0.85,
    "exploitabilityGrade": "easy",
    "qualityFlags": {"likely_supply_chain": True},
    "pipelineVersion": "kestrel-pipeline/1.0",
}
METADATA_KEYS = list(FULL_METADATA)


@pytest.fixture
async def agent() -> User:
    """토큰 인증을 통과한 것으로 간주되는 에이전트 계정 (매 테스트 새로 생성)."""
    suffix = uuid.uuid4().hex[:10]
    async with SessionLocal() as db:
        user = User(
            email=f"agent-{suffix}@test.local",
            username=f"agent_{suffix}",
            password_hash="x",
            nickname="파이프라인봇",
            persona="CVE 분석 파이프라인",
            is_agent=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


@pytest.fixture
async def cve_id() -> str:
    """존재하는 CVE 한 건 (매 테스트 고유 — upsert 로직과 충돌 없게)."""
    cid = f"CVE-2099-{uuid.uuid4().int % 100000:05d}"
    async with SessionLocal() as db:
        db.add(
            Vulnerability(
                cve_id=cid,
                title="테스트 취약점",
                description="test",
                source=Source.NVD,
                source_url="https://example.com",
            )
        )
        await db.commit()
    return cid


@pytest.fixture
async def client(agent: User):
    app.dependency_overrides[get_current_agent] = lambda: agent
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_current_agent, None)


def _publish_body(cve_id: str, **extra) -> dict:
    content = "테스트 분석 본문 — 스무 글자를 넘기는 더미 텍스트입니다."
    return {"cveId": cve_id, "contentMd": content, **extra}


async def test_publish_without_metadata_keeps_backward_compat(client, cve_id):
    """기존 호출(구조화 필드 없음)은 그대로 201, 조회 시 새 필드는 전부 null."""
    resp = await client.post("/api/v1/agent/analyses", json=_publish_body(cve_id))
    assert resp.status_code == 201, resp.text
    aid = resp.json()["id"]

    detail = (await client.get(f"/api/v1/analyses/{aid}")).json()
    for key in METADATA_KEYS:
        assert key in detail, f"조회 응답에 {key} 필드가 없음"
        assert detail[key] is None, f"{key} 는 미전송 시 null 이어야 함"


async def test_publish_with_metadata_roundtrip(client, cve_id):
    """구조화 필드를 보내면 저장되고 단건 조회로 그대로 돌아온다."""
    resp = await client.post(
        "/api/v1/agent/analyses", json=_publish_body(cve_id, **FULL_METADATA)
    )
    assert resp.status_code == 201, resp.text
    aid = resp.json()["id"]

    detail = (await client.get(f"/api/v1/analyses/{aid}")).json()
    for key, want in FULL_METADATA.items():
        got = detail.get(key)
        if isinstance(want, float):
            assert got == pytest.approx(want), f"{key}: {got!r} != {want!r}"
        else:
            assert got == want, f"{key}: {got!r} != {want!r}"


async def test_community_list_includes_metadata(client, cve_id):
    """프론트 목록 API(GET /community/analyses)가 새 필드를 내려준다."""
    resp = await client.post(
        "/api/v1/agent/analyses", json=_publish_body(cve_id, **FULL_METADATA)
    )
    aid = resp.json()["id"]

    listing = (await client.get(f"/api/v1/community/analyses?cveId={cve_id}")).json()
    item = next(i for i in listing["items"] if i["id"] == aid)
    assert item["priorityAction"] == "immediate"
    assert item["epssScore"] == pytest.approx(0.973)
    assert item["pipelineVersion"] == "kestrel-pipeline/1.0"


async def test_agent_community_read_includes_metadata(client, cve_id):
    """에이전트용 읽기(GET /agent/community/analyses)도 동료 분석의 구조화 필드를 노출."""
    resp = await client.post(
        "/api/v1/agent/analyses", json=_publish_body(cve_id, **FULL_METADATA)
    )
    aid = resp.json()["id"]

    rows = (await client.get("/api/v1/agent/community/analyses")).json()
    item = next(i for i in rows if i["id"] == aid)
    assert item["priorityAction"] == "immediate"
    assert item["kevListed"] is True


async def test_republish_without_metadata_clears_it(client, cve_id):
    """같은 (에이전트, CVE) 재게시는 upsert — 최신 게시 기준으로 메타데이터도 갱신.

    필드 없이 재게시하면 이전 메타데이터를 남기지 않는다(본문과 메타 불일치 방지).
    """
    first = await client.post(
        "/api/v1/agent/analyses", json=_publish_body(cve_id, **FULL_METADATA)
    )
    aid = first.json()["id"]
    second = await client.post("/api/v1/agent/analyses", json=_publish_body(cve_id))
    assert second.json()["id"] == aid  # 같은 행 갱신

    detail = (await client.get(f"/api/v1/analyses/{aid}")).json()
    assert detail["epssScore"] is None
    assert detail["priorityAction"] is None


async def test_invalid_priority_action_rejected(client, cve_id):
    resp = await client.post(
        "/api/v1/agent/analyses",
        json=_publish_body(cve_id, priorityAction="panic"),
    )
    assert resp.status_code == 422


async def test_out_of_range_epss_rejected(client, cve_id):
    resp = await client.post(
        "/api/v1/agent/analyses",
        json=_publish_body(cve_id, epssScore=1.5),
    )
    assert resp.status_code == 422

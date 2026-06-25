"""Kestrel MCP (Model Context Protocol) 서버 — 외부 AI 에이전트 노출용.

Claude·ChatGPT 등 MCP 지원 에이전트가 Kestrel 의 CVE 데이터를 "도구"로 직접
조회하도록 한다. Streamable HTTP 전송(JSON-RPC 2.0) 최소 구현:

    initialize · notifications/initialized · ping · tools/list · tools/call

설계/보안 원칙:
- **공개·읽기 전용만.** 이미 누구나 GET /cves 로 보는 데이터만 노출하며,
  인증·쓰기·관리·에이전트 토큰 등 어떤 비공개 표면도 건드리지 않는다.
- 모든 limit 은 상한을 두고, 쿼리는 파라미터 바인딩(주입 방지).
- 상태 비저장(stateless) — 세션 헤더 불필요. JSON 응답만 사용.
- 같은 FastAPI 백엔드에 얹어(/api/v1/mcp) 기존 DB·SSVC 로직을 재사용한다.

공개 URL: https://www.kestrel.forum/api/v1/mcp
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Severity, Vulnerability
from app.services.ssvc import remediation_for

router = APIRouter(tags=["mcp"])

_PROTOCOL_VERSION = "2025-06-18"
_SERVER_INFO = {"name": "kestrel", "title": "Kestrel CVE Intelligence", "version": "0.1.0"}
_INSTRUCTIONS = (
    "Kestrel 실시간 CVE·제로데이 인텔리전스. CVSS(이론)·EPSS(예측)·KEV(실측) 신호와 "
    "CISA SSVC 기준 권장 대응 기한(3/14/60일)을 제공합니다. 공개·읽기 전용 도구만 노출됩니다."
)

_MAX_LIMIT = 25


# ─── 도구 정의 (tools/list) ─────────────────────────────────────────
_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_cves",
        "description": (
            "키워드·심각도·KEV 로 CVE 를 검색한다(최신순). 공개 읽기 전용. "
            "각 결과는 CVE ID·제목·심각도·CVSS·EPSS·KEV·발행일을 담는다."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "CVE ID 또는 제목에 포함된 키워드"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "심각도 필터",
                },
                "kevOnly": {"type": "boolean", "description": "true 면 KEV(실측 악용) 등재만"},
                "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_LIMIT, "default": 10},
            },
        },
    },
    {
        "name": "get_cve",
        "description": "단일 CVE 의 상세(CVSS·EPSS·KEV·요약)와 CISA SSVC 권장 대응 기한을 반환한다.",
        "inputSchema": {
            "type": "object",
            "properties": {"cveId": {"type": "string", "description": "예: CVE-2024-3094"}},
            "required": ["cveId"],
        },
    },
    {
        "name": "get_remediation",
        "description": (
            "CVE 의 CISA SSVC 권장 대응 기한만 반환한다(3/14/60일 또는 차기 업그레이드 시) "
            "— KEV·자동화 가능성·기술 영향·노출 신호로 도출한 근거 포함."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"cveId": {"type": "string"}},
            "required": ["cveId"],
        },
    },
    {
        "name": "recent_kev",
        "description": "최근 KEV(Known Exploited Vulnerabilities, 실측 악용) 등재 CVE 목록을 최신순으로 반환한다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_LIMIT, "default": 10}
            },
        },
    },
]


def _clamp(v: Any, default: int = 10) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, _MAX_LIMIT))


def _sev_str(sev: Any) -> str | None:
    return sev.value if hasattr(sev, "value") else (str(sev) if sev else None)


def _vuln_brief(v: Vulnerability) -> dict[str, Any]:
    return {
        "cveId": v.cve_id,
        "title": v.title,
        "severity": _sev_str(v.severity),
        "cvssScore": float(v.cvss_score) if v.cvss_score is not None else None,
        "epssScore": float(v.epss_score) if v.epss_score is not None else None,
        "kevListed": bool(v.kev_listed),
        "publishedAt": v.published_at.isoformat() if v.published_at else None,
    }


# ─── 도구 구현 (공개 데이터 · 파라미터 바인딩) ──────────────────────
async def _tool_search_cves(db: AsyncSession, args: dict[str, Any]) -> dict[str, Any]:
    limit = _clamp(args.get("limit"))
    stmt = select(Vulnerability)
    q = (args.get("query") or "").strip()
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Vulnerability.cve_id.ilike(like), Vulnerability.title.ilike(like)))
    sev = args.get("severity")
    if sev:
        try:
            stmt = stmt.where(Vulnerability.severity == Severity(str(sev).lower()))
        except ValueError:
            pass
    if args.get("kevOnly") is True:
        stmt = stmt.where(Vulnerability.kev_listed.is_(True))
    stmt = stmt.order_by(Vulnerability.published_at.desc().nulls_last()).limit(limit)
    rows = (await db.execute(stmt)).scalars().unique().all()
    return {"count": len(rows), "items": [_vuln_brief(v) for v in rows]}


async def _load_vuln(db: AsyncSession, cve_id: str) -> Vulnerability | None:
    cid = (cve_id or "").strip()
    if not cid:
        return None
    return await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cid))


async def _tool_get_cve(db: AsyncSession, args: dict[str, Any]) -> dict[str, Any]:
    v = await _load_vuln(db, args.get("cveId", ""))
    if v is None:
        return {"error": "not_found", "cveId": args.get("cveId")}
    out = _vuln_brief(v)
    out["summary"] = v.summary or (v.description[:500] if v.description else None)
    out["cvssVector"] = v.cvss_vector
    out["sourceUrl"] = v.source_url
    out["remediation"] = remediation_for(v)
    return out


async def _tool_get_remediation(db: AsyncSession, args: dict[str, Any]) -> dict[str, Any]:
    v = await _load_vuln(db, args.get("cveId", ""))
    if v is None:
        return {"error": "not_found", "cveId": args.get("cveId")}
    return {"cveId": v.cve_id, "remediation": remediation_for(v)}


async def _tool_recent_kev(db: AsyncSession, args: dict[str, Any]) -> dict[str, Any]:
    limit = _clamp(args.get("limit"))
    rows = (
        await db.execute(
            select(Vulnerability)
            .where(Vulnerability.kev_listed.is_(True))
            .order_by(Vulnerability.kev_date_added.desc().nulls_last())
            .limit(limit)
        )
    ).scalars().unique().all()
    return {"count": len(rows), "items": [_vuln_brief(v) for v in rows]}


_TOOL_IMPL = {
    "search_cves": _tool_search_cves,
    "get_cve": _tool_get_cve,
    "get_remediation": _tool_get_remediation,
    "recent_kev": _tool_recent_kev,
}


# ─── JSON-RPC 헬퍼 ──────────────────────────────────────────────────
def _ok(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@router.get("/mcp")
async def mcp_get() -> Response:
    # 서버→클라이언트 SSE 스트림은 제공하지 않음(상태 비저장 읽기 전용) → 405.
    return Response(status_code=405, headers={"Allow": "POST"})


@router.post("/mcp")
async def mcp_post(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return _err(None, -32700, "Parse error")

    # 배치는 미지원 — 단일 메시지만.
    if not isinstance(body, dict):
        return _err(None, -32600, "Invalid Request")

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params") or {}

    # 알림(id 없음) — 응답 본문 없이 202.
    if req_id is None and isinstance(method, str) and method.startswith("notifications/"):
        return Response(status_code=202)

    if method == "initialize":
        client_ver = (params or {}).get("protocolVersion") or _PROTOCOL_VERSION
        return _ok(
            req_id,
            {
                "protocolVersion": client_ver,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": _SERVER_INFO,
                "instructions": _INSTRUCTIONS,
            },
        )

    if method == "ping":
        return _ok(req_id, {})

    if method == "tools/list":
        return _ok(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = (params or {}).get("name")
        args = (params or {}).get("arguments") or {}
        impl = _TOOL_IMPL.get(name)
        if impl is None:
            return _err(req_id, -32602, f"Unknown tool: {name}")
        try:
            data = await impl(db, args)
        except Exception as exc:  # noqa: BLE001 — 도구 오류는 isError 결과로 전달
            return _ok(
                req_id,
                {
                    "content": [{"type": "text", "text": f"도구 실행 오류: {exc}"}],
                    "isError": True,
                },
            )
        import json as _json

        text = _json.dumps(data, ensure_ascii=False, indent=2)
        return _ok(
            req_id,
            {"content": [{"type": "text", "text": text}], "structuredContent": data, "isError": False},
        )

    # 알림이 아닌 미지원 메서드.
    if req_id is None:
        return Response(status_code=202)
    return _err(req_id, -32601, f"Method not found: {method}")

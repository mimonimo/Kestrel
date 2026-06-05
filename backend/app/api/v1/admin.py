"""Operator endpoints — manual ingestion triggers with per-request key overrides.

The frontend settings page POSTs saved NVD / GitHub keys here so the user can
validate them with a fresh pull. Keys are used for the duration of the request
only; they are never written to the DB or env.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic import BaseModel as _PydBaseModel
from pydantic import ConfigDict as _PydConfigDict

from app.api.v1.deps import require_admin
from app.core.database import SessionLocal, get_db
from app.core.logging import get_logger
from app.models import AppSettings
from app.services.ingestion import run_parser
from app.services.parsers import ExploitDbParser, GithubAdvisoryParser, NvdParser
from app.services.parsers.mitre import MitreParser
from app.services.priority_signals import refresh_all as refresh_priority_signals

log = get_logger(__name__)

# 전체 router 에 admin 가드 — refresh / priority-signals / mitre-backfill
# 등 운영 명령은 모두 관리자만 호출. 일반 유저는 401/403.
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


# ─── 외부 데이터 소스 키 관리 (PR 10-CQ) ─────────────────────────────
# 응답에는 마스킹된 값만 (`****1234`) 노출. PUT 으로 저장.
# admin 본인이 웹 UI 에서 한 곳에서 관리 — 어디서 접속해도 같은 상태.


def _mask(value: str | None) -> str | None:
    if not value:
        return None
    tail = value[-4:] if len(value) >= 4 else value
    return f"****{tail}"


class _ExternalKeysCamel(_PydBaseModel):
    model_config = _PydConfigDict(alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ), populate_by_name=True)


class ExternalKeysOut(_ExternalKeysCamel):
    nvd_api_key: str | None = None
    github_token: str | None = None
    nvd_set: bool = False
    github_set: bool = False


class ExternalKeysUpdate(_ExternalKeysCamel):
    # ``None`` = 변경 안 함. 빈 문자열 = 삭제. 비-공백 문자열 = 새 값.
    nvd_api_key: str | None = None
    github_token: str | None = None


@router.get(
    "/external-keys",
    response_model=ExternalKeysOut,
    response_model_by_alias=True,
)
async def get_external_keys(db: AsyncSession = Depends(get_db)) -> ExternalKeysOut:
    row = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
    nvd = row.nvd_api_key if row else None
    gh = row.github_token if row else None
    return ExternalKeysOut(
        nvd_api_key=_mask(nvd),
        github_token=_mask(gh),
        nvd_set=bool(nvd),
        github_set=bool(gh),
    )


# ─── 사용자 관리 (PR 10-CR) ────────────────────────────────────────
# admin 이 모든 사용자 목록을 보고 role 을 변경하거나 계정을 삭제.
# 안전 가드:
#   - 자기 자신의 role 변경 / 삭제 불가 (lock-out 방지)
#   - INITIAL_ADMIN_EMAILS 매칭되는 계정은 강등해도 다음 로그인/가입 시 자동 admin 회복

from datetime import datetime as _dt

from app.core.audit import ACTION_LABELS, AuditAction, record_audit
from app.core.security import is_admin_email
from app.models import AnalysisResult as _AnalysisResult
from app.models import AuditLog as _AuditLog
from app.models import Bookmark as _Bookmark
from app.models import Comment as _Comment
from app.models import LoginLog as _LoginLog
from app.models import Post as _Post
from app.models import User as _User
from app.models import UserRole as _UserRole


class _UserStats(_PydBaseModel):
    """사용자별 활동 카운트 — 추적용 메타. 모두 count(*) 라 인덱스로 빠름."""

    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    analyses: int = 0
    posts: int = 0
    comments: int = 0
    bookmarks: int = 0
    last_activity_at: _dt | None = None


class _UserOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    id: str
    email: str
    username: str
    nickname: str | None = None
    role: str
    is_admin: bool
    created_at: _dt
    updated_at: _dt
    last_login_at: _dt | None = None
    last_active_at: _dt | None = None  # 최근 활동(요청) 시각 — 웹 접속 로그 기반
    stats: _UserStats = _UserStats()


class _LoginLogOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    id: int
    user_id: str
    ip: str | None = None
    user_agent: str | None = None
    # PR 10-DK — UA 파싱 결과. ua-parser 가 OS/브라우저/디바이스 분리.
    os_name: str | None = None
    os_version: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    device_kind: str | None = None  # desktop / mobile / tablet / bot / unknown
    created_at: _dt


class _LoginLogsList(_PydBaseModel):
    items: list[_LoginLogOut]
    total: int


class _AuditLogOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    id: int
    action: str
    action_label: str | None = None
    actor_label: str | None = None
    actor_user_id: str | None = None
    target: str | None = None
    detail: str | None = None
    ip: str | None = None
    created_at: _dt


class _AuditLogsList(_PydBaseModel):
    items: list[_AuditLogOut]
    total: int


class _AccessLogOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    id: int
    user_id: str
    user_label: str | None = None
    ip: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    device_kind: str | None = None
    created_at: _dt


class _AccessLogsList(_PydBaseModel):
    items: list[_AccessLogOut]
    total: int


class _ActivityLogOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    kind: str          # post / comment / analysis / bookmark
    kind_label: str
    actor_label: str | None = None
    actor_user_id: str | None = None
    ref: str | None = None       # cveId / 제목 등
    created_at: _dt


class _ActivityLogsList(_PydBaseModel):
    items: list[_ActivityLogOut]
    total: int


_ACTIVITY_LABELS = {
    "post": "글 작성",
    "comment": "댓글",
    "analysis": "AI 분석",
    "bookmark": "즐겨찾기",
}


# UA 파싱 — 매 요청 마다 새로 파싱하면 부담이라 lru_cache.
from functools import lru_cache as _lru_cache


@_lru_cache(maxsize=2048)
def _parse_ua(ua: str | None) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """(os_name, os_version, browser_name, browser_version, device_kind)."""
    if not ua:
        return None, None, None, None, None
    try:
        from ua_parser import user_agent_parser  # type: ignore

        parsed = user_agent_parser.Parse(ua)
        os_d = parsed.get("os") or {}
        ua_d = parsed.get("user_agent") or {}
        dev_d = parsed.get("device") or {}
        os_name = os_d.get("family") or None
        os_ver_parts = [str(os_d.get(k)) for k in ("major", "minor", "patch") if os_d.get(k)]
        os_version = ".".join(os_ver_parts) or None
        browser_name = ua_d.get("family") or None
        ua_ver_parts = [str(ua_d.get(k)) for k in ("major", "minor", "patch") if ua_d.get(k)]
        browser_version = ".".join(ua_ver_parts) or None

        low = ua.lower()
        if "bot" in low or "crawler" in low or "spider" in low:
            kind = "bot"
        elif dev_d.get("family", "").lower() in {"iphone", "android", "windows phone"} or "mobile" in low:
            kind = "mobile"
        elif "ipad" in low or "tablet" in low:
            kind = "tablet"
        else:
            kind = "desktop"
        return os_name, os_version, browser_name, browser_version, kind
    except Exception:  # noqa: BLE001
        return None, None, None, None, None


class _UsersList(_PydBaseModel):
    items: list[_UserOut]
    total: int


class _RoleUpdate(_PydBaseModel):
    role: str  # "user" | "expert" | "admin"


def _to_user_out(
    u: _User, stats: _UserStats | None = None, last_active_at: _dt | None = None
) -> _UserOut:
    role_val = u.role.value if hasattr(u.role, "value") else str(u.role)
    return _UserOut(
        id=str(u.id),
        email=u.email,
        username=u.username,
        nickname=u.nickname,
        role=role_val,
        is_admin=u.role == _UserRole.ADMIN,
        created_at=u.created_at,
        updated_at=u.updated_at,
        last_login_at=u.last_login_at,
        last_active_at=last_active_at,
        stats=stats or _UserStats(),
    )


@router.get(
    "/users/{user_id}/login-logs",
    response_model=_LoginLogsList,
    response_model_by_alias=True,
)
async def list_user_login_logs(
    user_id: str,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
) -> _LoginLogsList:
    import uuid as _uuid
    try:
        uid = _uuid.UUID(user_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.") from None
    target = await db.scalar(select(_User).where(_User.id == uid))
    if target is None:
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.")
    from sqlalchemy import desc as _desc
    rows = (
        await db.execute(
            select(_LoginLog)
            .where(_LoginLog.user_id == uid)
            .order_by(_desc(_LoginLog.created_at))
            .limit(max(1, min(200, limit)))
        )
    ).scalars().all()
    items = []
    for r in rows:
        os_name, os_ver, br_name, br_ver, kind = _parse_ua(r.user_agent)
        items.append(
            _LoginLogOut(
                id=r.id,
                user_id=str(r.user_id),
                ip=r.ip,
                user_agent=r.user_agent,
                os_name=os_name,
                os_version=os_ver,
                browser_name=br_name,
                browser_version=br_ver,
                device_kind=kind,
                created_at=r.created_at,
            )
        )
    return _LoginLogsList(items=items, total=len(items))


@router.get("/audit/logs", response_model=_AuditLogsList, response_model_by_alias=True)
async def list_audit_logs(
    action: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> _AuditLogsList:
    """전역 감사 피드 — 로그인 성공/실패·가입·비번 변경·역할 변경·삭제·키 변경 등을
    시간 역순으로. ``action`` 으로 특정 이벤트만 필터."""
    from sqlalchemy import desc as _desc

    stmt = select(_AuditLog).order_by(_desc(_AuditLog.created_at)).limit(limit)
    if action:
        stmt = (
            select(_AuditLog)
            .where(_AuditLog.action == action)
            .order_by(_desc(_AuditLog.created_at))
            .limit(limit)
        )
    rows = (await db.execute(stmt)).scalars().all()
    items = [
        _AuditLogOut(
            id=r.id,
            action=r.action,
            action_label=ACTION_LABELS.get(r.action),
            actor_label=r.actor_label,
            actor_user_id=str(r.actor_user_id) if r.actor_user_id else None,
            target=r.target,
            detail=r.detail,
            ip=r.ip,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return _AuditLogsList(items=items, total=len(items))


@router.get("/audit/actions")
async def list_audit_actions() -> dict:
    """필터 UI 용 — 액션 코드→라벨 매핑."""
    return {"actions": ACTION_LABELS}


@router.get("/overview")
async def admin_overview(db: AsyncSession = Depends(get_db)) -> dict:
    """이용자/활동 개요 — 간단한 시각화용 집계."""
    from datetime import datetime as _now_dt
    from datetime import timedelta as _td
    from datetime import timezone as _tz

    from sqlalchemy import func as _func

    now = _now_dt.now(_tz.utc)
    since7 = now - _td(days=7)

    async def _count(stmt) -> int:
        return int((await db.execute(stmt)).scalar_one() or 0)

    total_users = await _count(select(_func.count()).select_from(_User))
    admin_users = await _count(
        select(_func.count()).select_from(_User).where(_User.role == _UserRole.ADMIN)
    )
    new_users_7d = await _count(
        select(_func.count()).select_from(_User).where(_User.created_at >= since7)
    )
    logins_7d = await _count(
        select(_func.count()).select_from(_LoginLog).where(_LoginLog.created_at >= since7)
    )
    posts = await _count(
        select(_func.count()).select_from(_Post).where(_Post.user_id.isnot(None))
    )
    comments = await _count(
        select(_func.count()).select_from(_Comment).where(_Comment.user_id.isnot(None))
    )
    analyses = await _count(select(_func.count()).select_from(_AnalysisResult))
    bookmarks = await _count(
        select(_func.count()).select_from(_Bookmark).where(_Bookmark.user_id.isnot(None))
    )

    # 방문 통계 — Redis SET 기반 순 방문자. 회원/비회원 분리 분석.
    #   visitors:day:<KST>        전체(회원+비회원)
    #   visitors:auth:day:<KST>   회원(로그인 상태) — 비회원 추정 = 전체 − 회원
    # 일별 키는 7일 보존이라 최근 7일 추이까지 분석 가능. Redis 장애 시 0 처리.
    visits = {"total": 0, "today": 0, "memberTotal": 0, "anonTotal": 0, "daily": []}
    try:
        from app.core.redis_client import get_redis as _get_redis

        kst = _tz(_td(hours=9))
        today = _now_dt.now(kst).date()
        redis = await _get_redis()
        daily = []
        for i in range(6, -1, -1):
            day = today - _td(days=i)
            iso = day.isoformat()
            total_d = int(await redis.scard(f"visitors:day:{iso}") or 0)
            member_d = int(await redis.scard(f"visitors:auth:day:{iso}") or 0)
            daily.append(
                {
                    "date": iso,
                    "total": total_d,
                    "member": member_d,
                    "anon": max(0, total_d - member_d),
                }
            )
        total = int(await redis.scard("visitors:all") or 0)
        member_total = int(await redis.scard("visitors:auth:all") or 0)
        visits = {
            "total": total,
            "today": daily[-1]["total"] if daily else 0,
            "memberTotal": member_total,
            "anonTotal": max(0, total - member_total),
            "daily": daily,
        }
    except Exception:  # noqa: BLE001 — 방문 통계 실패가 개요 전체를 막지 않도록
        pass

    return {
        "totalUsers": total_users,
        "adminUsers": admin_users,
        "newUsers7d": new_users_7d,
        "logins7d": logins_7d,
        "activity": {
            "post": posts,
            "comment": comments,
            "analysis": analyses,
            "bookmark": bookmarks,
        },
        "visits": visits,
    }


def _user_label(u: _User | None) -> str | None:
    if u is None:
        return None
    return u.nickname or u.username or u.email


@router.get("/access-logs", response_model=_AccessLogsList, response_model_by_alias=True)
async def list_access_logs(
    limit: int = Query(default=100, ge=1, le=300),
    db: AsyncSession = Depends(get_db),
) -> _AccessLogsList:
    """전역 접속(로그인 성공) 로그 — 전체 사용자, 시간 역순. UA 파싱 + 사용자 라벨."""
    from sqlalchemy import desc as _desc

    rows = (
        await db.execute(
            select(_LoginLog, _User)
            .join(_User, _User.id == _LoginLog.user_id, isouter=True)
            .order_by(_desc(_LoginLog.created_at))
            .limit(limit)
        )
    ).all()
    items = []
    for log_row, user_row in rows:
        os_name, os_ver, br_name, br_ver, kind = _parse_ua(log_row.user_agent)
        items.append(
            _AccessLogOut(
                id=log_row.id,
                user_id=str(log_row.user_id),
                user_label=_user_label(user_row),
                ip=log_row.ip,
                os_name=os_name,
                os_version=os_ver,
                browser_name=br_name,
                browser_version=br_ver,
                device_kind=kind,
                created_at=log_row.created_at,
            )
        )
    return _AccessLogsList(items=items, total=len(items))


class _AnonAccessLogOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    ip: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    device_kind: str | None = None
    created_at: str | None = None


class _AnonAccessLogsList(_PydBaseModel):
    items: list[_AnonAccessLogOut]
    total: int


@router.get("/anon-access-logs", response_model=_AnonAccessLogsList, response_model_by_alias=True)
async def list_anon_access_logs(
    limit: int = Query(default=150, ge=1, le=1000),
) -> _AnonAccessLogsList:
    """비회원(비로그인) 접속 로그 — /stats/visitors 가 비회원 '오늘 첫 방문' 을
    Redis capped list 에 적재한 것. 최근순."""
    import json as _json

    from app.core.redis_client import get_redis as _get_redis

    items: list[_AnonAccessLogOut] = []
    try:
        redis = await _get_redis()
        raw = await redis.lrange("visitors:anon:log", 0, limit - 1)
        for s in raw:
            try:
                rec = _json.loads(s)
            except Exception:  # noqa: BLE001
                continue
            os_name, os_ver, br_name, br_ver, kind = _parse_ua(rec.get("ua"))
            items.append(
                _AnonAccessLogOut(
                    ip=rec.get("ip"),
                    os_name=os_name,
                    os_version=os_ver,
                    browser_name=br_name,
                    browser_version=br_ver,
                    device_kind=kind,
                    created_at=rec.get("ts"),
                )
            )
    except Exception:  # noqa: BLE001 — Redis 장애 시 빈 목록
        pass
    return _AnonAccessLogsList(items=items, total=len(items))


class _WebAccessLogOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    method: str
    path: str
    status: int
    duration_ms: float | None = None
    ip: str | None = None
    user_label: str | None = None
    os_name: str | None = None
    browser_name: str | None = None
    device_kind: str | None = None
    created_at: float


class _WebAccessLogsList(_PydBaseModel):
    items: list[_WebAccessLogOut]
    total: int


@router.get("/web-access-log", response_model=_WebAccessLogsList, response_model_by_alias=True)
async def web_access_log(
    method: str | None = Query(default=None),
    status_class: str | None = Query(default=None),  # 2xx/3xx/4xx/5xx
    q: str | None = Query(default=None, max_length=200),
    uid: str | None = Query(default=None),  # 특정 회원의 요청만 (drill-down)
    ip: str | None = Query(default=None),   # 특정 IP 의 요청만 (drill-down)
    limit: int = Query(default=200, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
) -> _WebAccessLogsList:
    """웹 접속 로그(Apache 스타일) — 미들웨어가 적재한 요청별 기록. 최근순.
    method / status_class / q(경로) / uid(회원) / ip 필터."""
    import uuid as _uuid

    from app.core.access_log import read_recent

    recs = await read_recent(5000)

    # 필터
    if method:
        m = method.upper()
        recs = [r for r in recs if (r.get("method") or "").upper() == m]
    if status_class and status_class[:1].isdigit():
        head = status_class[0]
        recs = [r for r in recs if str(r.get("status", "")).startswith(head)]
    if q:
        ql = q.lower()
        recs = [r for r in recs if ql in (r.get("path") or "").lower()]
    if uid:
        recs = [r for r in recs if r.get("uid") == uid]
    if ip:
        recs = [r for r in recs if (r.get("ip") or "") == ip]
    recs = recs[:limit]

    # uid → 사용자 라벨 일괄 조회
    uids: set[_uuid.UUID] = set()
    for r in recs:
        raw = r.get("uid")
        if raw:
            try:
                uids.add(_uuid.UUID(raw))
            except (ValueError, TypeError):
                pass
    labels: dict[str, str] = {}
    if uids:
        rows = (await db.execute(select(_User).where(_User.id.in_(uids)))).scalars().all()
        for u in rows:
            labels[str(u.id)] = u.nickname or u.username or u.email

    items = []
    for r in recs:
        os_name, _osv, br_name, _brv, kind = _parse_ua(r.get("ua"))
        items.append(
            _WebAccessLogOut(
                method=r.get("method") or "",
                path=r.get("path") or "",
                status=int(r.get("status") or 0),
                duration_ms=r.get("ms"),
                ip=r.get("ip"),
                user_label=labels.get(r.get("uid") or ""),
                os_name=os_name,
                browser_name=br_name,
                device_kind=kind,
                created_at=float(r.get("ts") or 0),
            )
        )
    return _WebAccessLogsList(items=items, total=len(items))


class _AccessSummaryOut(_PydBaseModel):
    model_config = _PydConfigDict(populate_by_name=True, alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ))
    ip: str = ""
    user_id: str | None = None       # group=user 일 때 회원 id (drill-down)
    label: str = ""                  # 화면 표시용 (IP 또는 회원 라벨)
    request_count: int
    distinct_paths: int
    is_anon: bool
    member_labels: list[str] = []
    top_path: str | None = None
    os_name: str | None = None
    browser_name: str | None = None
    device_kind: str | None = None
    first_at: float = 0
    last_at: float = 0


class _AccessSummaryList(_PydBaseModel):
    items: list[_AccessSummaryOut]
    total: int


@router.get("/access-summary", response_model=_AccessSummaryList, response_model_by_alias=True)
async def access_summary(
    group: str = Query(default="ip"),       # ip(출처별) / user(회원별)
    who: str | None = Query(default=None),  # member / anon / None — group=ip 일 때만
    q: str | None = Query(default=None, max_length=200),
    min_count: int = Query(default=1, ge=1, le=100000),
    limit: int = Query(default=300, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
) -> _AccessSummaryList:
    """접속 요약 — group=ip: 출처(IP)별(모르는 외부/비회원·과다 요청 추적),
    group=user: 회원별(최근 활동=요청 시간). 요청 많은 순. who·검색·최소요청수 필터."""
    import uuid as _uuid
    from collections import Counter

    from app.core.access_log import read_recent

    recs = await read_recent(5000)
    by_user = group == "user"

    agg: dict[str, dict] = {}
    for r in recs:
        uid = r.get("uid")
        if by_user:
            if not uid:
                continue
            key = uid
        else:
            if who == "member" and not uid:
                continue
            if who == "anon" and uid:
                continue
            key = r.get("ip") or "unknown"
        a = agg.get(key)
        if a is None:
            a = {"count": 0, "paths": Counter(), "uids": set(), "first": 0, "last": 0, "ua": r.get("ua")}
            agg[key] = a
        a["count"] += 1
        if r.get("path"):
            a["paths"][r["path"]] += 1
        if uid:
            a["uids"].add(uid)
        ts = r.get("ts") or 0
        a["first"] = min(a["first"], ts) if a["first"] else ts
        a["last"] = max(a["last"], ts)

    # uid → 라벨
    all_uids: set[_uuid.UUID] = set()
    if by_user:
        for k in agg:
            try:
                all_uids.add(_uuid.UUID(k))
            except (ValueError, TypeError):
                pass
    else:
        for a in agg.values():
            for raw in a["uids"]:
                try:
                    all_uids.add(_uuid.UUID(raw))
                except (ValueError, TypeError):
                    pass
    labels: dict[str, str] = {}
    if all_uids:
        rows = (await db.execute(select(_User).where(_User.id.in_(all_uids)))).scalars().all()
        for u in rows:
            labels[str(u.id)] = u.nickname or u.username or u.email

    ql = q.lower() if q else None
    items = []
    for key, a in agg.items():
        if a["count"] < min_count:
            continue
        os_name, _v, br_name, _b, kind = _parse_ua(a["ua"])
        top_path = a["paths"].most_common(1)[0][0] if a["paths"] else None
        if by_user:
            label = labels.get(key, "(삭제된 사용자)")
            if ql and ql not in label.lower():
                continue
            items.append(
                _AccessSummaryOut(
                    user_id=key, label=label, request_count=a["count"],
                    distinct_paths=len(a["paths"]), is_anon=False,
                    member_labels=[label], top_path=top_path,
                    os_name=os_name, browser_name=br_name, device_kind=kind,
                    first_at=float(a["first"] or 0), last_at=float(a["last"] or 0),
                )
            )
        else:
            if ql and ql not in key.lower():
                continue
            member_labels = [labels.get(u, "회원") for u in a["uids"]]
            items.append(
                _AccessSummaryOut(
                    ip=key, label=key, request_count=a["count"],
                    distinct_paths=len(a["paths"]), is_anon=len(a["uids"]) == 0,
                    member_labels=member_labels[:5], top_path=top_path,
                    os_name=os_name, browser_name=br_name, device_kind=kind,
                    first_at=float(a["first"] or 0), last_at=float(a["last"] or 0),
                )
            )
    items.sort(key=lambda x: x.request_count, reverse=True)
    items = items[:limit]
    return _AccessSummaryList(items=items, total=len(items))


@router.delete("/access-logs", status_code=204)
async def clear_access_logs(
    request: Request,
    ip: str | None = Query(default=None),
    uid: str | None = Query(default=None),
    me=Depends(require_admin),
) -> None:
    """접속 로그 비우기. ip/uid 지정 시 해당 출처/회원 로그만, 미지정 시 전체.
    감사 로그에 기록(별도 commit)."""
    from app.core.access_log import clear as _clear

    await _clear(ip=ip, uid=uid)
    detail = (
        f"IP {ip} 로그 삭제" if ip
        else f"회원 {uid} 로그 삭제" if uid
        else "전체 접속 로그 삭제"
    )
    async with SessionLocal() as _db:  # type: ignore[misc]
        await record_audit(
            _db, action="access_logs.clear", actor=me, request=request, detail=detail,
        )


@router.get("/activity-logs", response_model=_ActivityLogsList, response_model_by_alias=True)
async def list_activity_logs(
    kind: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=300),
    db: AsyncSession = Depends(get_db),
) -> _ActivityLogsList:
    """전역 활동 로그 — 글·댓글·AI분석·즐겨찾기 생성 이벤트를 시간순 병합.

    기존 데이터에서 직접 조회하므로 과거 활동도 소급 표시. 각 테이블에서 최근
    limit 건씩 가져와 created_at 기준 병합 후 상위 limit 건만 반환.
    """
    from sqlalchemy import desc as _desc

    merged: list[_ActivityLogOut] = []

    async def _collect(stmt, kind_code: str, ref_fn) -> None:
        rows = (await db.execute(stmt)).all()
        for entity, user_row in rows:
            merged.append(
                _ActivityLogOut(
                    kind=kind_code,
                    kind_label=_ACTIVITY_LABELS[kind_code],
                    actor_label=_user_label(user_row),
                    actor_user_id=str(entity.user_id) if entity.user_id else None,
                    ref=ref_fn(entity),
                    created_at=entity.created_at,
                )
            )

    wanted = {kind} if kind else {"post", "comment", "analysis", "bookmark"}

    if "post" in wanted:
        await _collect(
            select(_Post, _User)
            .join(_User, _User.id == _Post.user_id, isouter=True)
            .where(_Post.user_id.isnot(None))
            .order_by(_desc(_Post.created_at)).limit(limit),
            "post", lambda e: e.title,
        )
    if "comment" in wanted:
        await _collect(
            select(_Comment, _User)
            .join(_User, _User.id == _Comment.user_id, isouter=True)
            .where(_Comment.user_id.isnot(None))
            .order_by(_desc(_Comment.created_at)).limit(limit),
            "comment", lambda e: (e.content or "")[:60],
        )
    if "analysis" in wanted:
        await _collect(
            select(_AnalysisResult, _User)
            .join(_User, _User.id == _AnalysisResult.user_id, isouter=True)
            .order_by(_desc(_AnalysisResult.created_at)).limit(limit),
            "analysis", lambda e: e.cve_id,
        )
    if "bookmark" in wanted:
        await _collect(
            select(_Bookmark, _User)
            .join(_User, _User.id == _Bookmark.user_id, isouter=True)
            .where(_Bookmark.user_id.isnot(None))
            .order_by(_desc(_Bookmark.created_at)).limit(limit),
            "bookmark", lambda e: e.cve_id,
        )

    merged.sort(key=lambda x: x.created_at, reverse=True)
    return _ActivityLogsList(items=merged[:limit], total=len(merged[:limit]))


@router.get("/users", response_model=_UsersList, response_model_by_alias=True)
async def list_users(
    q: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> _UsersList:
    """전체 사용자 목록 + 활동 통계. ``q`` 로 email/username/nickname 부분 검색."""
    from sqlalchemy import func as _func, or_ as _or

    from app.models import AnalysisResult, Bookmark, Comment, Post

    stmt = select(_User).order_by(_User.created_at.desc())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            _or(
                _User.email.ilike(like),
                _User.username.ilike(like),
                _User.nickname.ilike(like),
            )
        )
    users = (await db.execute(stmt.limit(500))).scalars().all()
    if not users:
        return _UsersList(items=[], total=0)

    uids = [u.id for u in users]

    async def _count_by_user(model, label: str) -> dict:
        rows = (
            await db.execute(
                select(model.user_id, _func.count(model.id))
                .where(model.user_id.in_(uids))
                .group_by(model.user_id)
            )
        ).all()
        return {uid: cnt for uid, cnt in rows}

    async def _max_created_by_user(model) -> dict:
        rows = (
            await db.execute(
                select(model.user_id, _func.max(model.created_at))
                .where(model.user_id.in_(uids))
                .group_by(model.user_id)
            )
        ).all()
        return {uid: ts for uid, ts in rows}

    analyses_by = await _count_by_user(AnalysisResult, "analyses")
    posts_by = await _count_by_user(Post, "posts")
    comments_by = await _count_by_user(Comment, "comments")
    bookmarks_by = await _count_by_user(Bookmark, "bookmarks")

    last_analysis = await _max_created_by_user(AnalysisResult)
    last_post = await _max_created_by_user(Post)
    last_comment = await _max_created_by_user(Comment)
    last_bookmark = await _max_created_by_user(Bookmark)

    # 웹 접속 로그 기반 회원별 마지막 요청(활동) 시각.
    from datetime import timezone as _utc

    from app.core.access_log import read_recent as _read_access

    last_req: dict[str, _dt] = {}
    try:
        for r in await _read_access(5000):
            ruid = r.get("uid")
            ts = r.get("ts")
            if not ruid or not ts:
                continue
            cur = last_req.get(ruid)
            dt = _dt.fromtimestamp(float(ts), tz=_utc.utc)
            if cur is None or dt > cur:
                last_req[ruid] = dt
    except Exception:  # noqa: BLE001
        last_req = {}

    items: list[_UserOut] = []
    for u in users:
        candidates = [
            last_analysis.get(u.id),
            last_post.get(u.id),
            last_comment.get(u.id),
            last_bookmark.get(u.id),
            u.updated_at,  # 프로필 변경 등도 활동으로 간주
        ]
        last = max([c for c in candidates if c is not None], default=None)
        stats = _UserStats(
            analyses=int(analyses_by.get(u.id, 0)),
            posts=int(posts_by.get(u.id, 0)),
            comments=int(comments_by.get(u.id, 0)),
            bookmarks=int(bookmarks_by.get(u.id, 0)),
            last_activity_at=last,
        )
        items.append(_to_user_out(u, stats, last_active_at=last_req.get(str(u.id))))
    return _UsersList(items=items, total=len(items))


@router.patch("/users/{user_id}/role", response_model=_UserOut, response_model_by_alias=True)
async def update_user_role(
    user_id: str,
    body: _RoleUpdate,
    request: Request,
    me=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> _UserOut:
    """USER ↔ EXPERT ↔ ADMIN 변경. 자기 자신 변경 차단."""
    import uuid as _uuid
    try:
        uid = _uuid.UUID(user_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.") from None
    if uid == me.id:
        raise HTTPException(400, detail="자기 자신의 권한은 변경할 수 없습니다.")
    target = await db.scalar(select(_User).where(_User.id == uid))
    if target is None:
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.")
    try:
        new_role = _UserRole(body.role)
    except ValueError:
        raise HTTPException(400, detail="허용되지 않은 role 입니다.") from None
    old_role = target.role.value if hasattr(target.role, "value") else str(target.role)
    target.role = new_role
    await db.commit()
    await db.refresh(target)
    log.info("admin.user_role_changed", target_id=str(target.id), new_role=new_role.value)
    await record_audit(
        db, action=AuditAction.USER_ROLE_CHANGE, actor=me, request=request,
        target=target.email, detail=f"{old_role} → {new_role.value}",
    )
    return _to_user_out(target)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    request: Request,
    me=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """사용자 삭제. 자기 자신 삭제 차단 + INITIAL_ADMIN_EMAILS 매칭 사용자 차단
    (실수로 부트스트랩 admin 을 지워 락아웃 되는 것 방지)."""
    import uuid as _uuid
    try:
        uid = _uuid.UUID(user_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.") from None
    if uid == me.id:
        raise HTTPException(400, detail="자기 자신은 삭제할 수 없습니다.")
    target = await db.scalar(select(_User).where(_User.id == uid))
    if target is None:
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.")
    if is_admin_email(target.email):
        raise HTTPException(
            400,
            detail=(
                "INITIAL_ADMIN_EMAILS 에 등록된 부트스트랩 관리자입니다 — "
                "환경변수에서 먼저 제외한 뒤 삭제하세요."
            ),
        )
    target_email = target.email
    await db.delete(target)
    await db.commit()
    log.info("admin.user_deleted", target_id=str(target.id))
    await record_audit(
        db, action=AuditAction.USER_DELETE, actor=me, request=request,
        target=target_email,
    )


@router.put(
    "/external-keys",
    response_model=ExternalKeysOut,
    response_model_by_alias=True,
)
async def put_external_keys(
    body: ExternalKeysUpdate,
    request: Request,
    me=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ExternalKeysOut:
    row = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
    if row is None:
        row = AppSettings(id=1)
        db.add(row)
    fields = body.model_fields_set
    actions: list[str] = []
    if "nvd_api_key" in fields or "nvdApiKey" in fields:
        new_val = (body.nvd_api_key or "").strip()
        if new_val:
            row.nvd_api_key = new_val
            actions.append("nvd_set")
        else:
            row.nvd_api_key = None
            actions.append("nvd_cleared")
    if "github_token" in fields or "githubToken" in fields:
        new_val = (body.github_token or "").strip()
        if new_val:
            row.github_token = new_val
            actions.append("gh_set")
        else:
            row.github_token = None
            actions.append("gh_cleared")
    await db.commit()
    # 토큰 자체는 로깅 X — 누가 어떤 액션을 했는지만.
    if actions:
        log.info("admin.external_keys_updated", actions=actions)
        await record_audit(
            db, action=AuditAction.ADMIN_KEYS_UPDATE, actor=me, request=request,
            detail=", ".join(actions),
        )
    return await get_external_keys(db)


@router.post("/refresh")
async def refresh_ingestion(
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    x_nvd_api_key: str | None = Header(default=None, alias="X-NVD-API-Key"),
    x_github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
    full_resync: str | None = Header(default=None, alias="X-Full-Resync"),
) -> dict:
    """Kick off one ingestion run per source, using the provided keys if any.

    Runs in the background so the HTTP call returns immediately — the caller
    should poll ``/status`` to see each source's latest log row update.

    PR 10-AJ: when keys are provided, persist them to ``app_settings`` so
    the background scheduler also uses them on subsequent ticks (previously
    only this-request was authenticated; scheduler ran token-less and GHSA
    returned 0 rows).

    ``X-Full-Resync: ghsa`` (or ``all``) bypasses the per-source
    ``last_success`` watermark so the parser walks from its natural
    beginning again. Use this to recover from a since-window gap — when
    earlier runs returned 0 items due to a transient token issue,
    ``finished_at`` advanced past advisories that were never actually
    fetched.
    """
    row = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
    if x_nvd_api_key or x_github_token:
        if row is None:
            row = AppSettings(id=1)
            db.add(row)
        if x_nvd_api_key:
            row.nvd_api_key = x_nvd_api_key
        if x_github_token:
            row.github_token = x_github_token
        await db.commit()

    # Fall back to persisted keys when the caller didn't send headers —
    # the scheduler already does this (jobs._resolve_external_keys), so
    # without this fallback "전체 다시 받기" from a device without the
    # key in localStorage runs token-less and fails the same way the
    # original since-window gap was caused.
    nvd_token = x_nvd_api_key or (row.nvd_api_key if row else None)
    gh_token = x_github_token or (row.github_token if row else None)

    resync_tokens = {t.strip().lower() for t in (full_resync or "").split(",") if t.strip()}
    ghsa_full = "ghsa" in resync_tokens or "all" in resync_tokens
    nvd_full = "nvd" in resync_tokens or "all" in resync_tokens
    edb_full = "exploit_db" in resync_tokens or "all" in resync_tokens
    # MITRE 는 별도 소스 — 과거엔 설정 화면의 전용 카드로만 돌렸지만, 이제
    # 대시보드 "동기화" 한 번으로 4개 소스를 전부 긁도록 여기에 합류시킨다.
    # 평상시엔 delta(최근 14일 git 변경분), "전체 다시 받기(all/mitre)" 일 때만
    # full(~340k) 로 걷는다.
    mitre_full = "mitre" in resync_tokens or "all" in resync_tokens

    async def _run_all() -> None:
        await asyncio.gather(
            run_parser(NvdParser(api_key_override=nvd_token), full_resync=nvd_full),
            run_parser(
                GithubAdvisoryParser(token_override=gh_token),
                full_resync=ghsa_full,
            ),
            run_parser(ExploitDbParser(), full_resync=edb_full),
            run_parser(
                MitreParser(
                    mode="full" if mitre_full else "delta",
                    since_days=14,
                )
            ),
            return_exceptions=True,
        )

    background.add_task(_run_all)
    return {
        "queued": True,
        "usedKeys": {
            "nvd": bool(nvd_token),
            "github": bool(gh_token),
        },
        "fullResync": {
            "nvd": nvd_full,
            "ghsa": ghsa_full,
            "exploit_db": edb_full,
            "mitre": mitre_full,
        },
    }


@router.post("/refresh-priority-signals")
async def refresh_priority_signals_endpoint(background: BackgroundTasks) -> dict:
    """Pull the current CISA KEV catalog + FIRST EPSS snapshot and update
    matching CVE rows. Runs in the background — poll the same row from
    /dashboard/insights to see counts move."""
    background.add_task(refresh_priority_signals)
    return {"queued": True}


class _CamelOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class MitreBackfillRequest(_CamelOut):
    # 'full' walks every CVE JSON in the repo (~340k); 'delta' only files
    # touched by git in the last ``since_days``.
    mode: str = Field(default="delta", pattern="^(full|delta)$")
    since_days: int = Field(default=14, ge=1, le=365)
    # Cap for safety / progress dry-runs. ``None`` = no cap.
    max_records: int | None = Field(default=None, ge=1, le=400_000)


class MitreBackfillResponse(_CamelOut):
    queued: bool
    mode: str
    detail: str


@router.post(
    "/mitre-backfill",
    response_model=MitreBackfillResponse,
    response_model_by_alias=True,
)
async def mitre_backfill(
    body: MitreBackfillRequest, background: BackgroundTasks
) -> MitreBackfillResponse:
    """Trigger a one-shot MITRE cvelistV5 ingestion.

    Full mode covers ~340k records and takes 30-60+ min on first run
    (mostly the initial git clone of ~5GB). Delta mode catches up the
    last ``since_days`` of changes — typical daily run, finishes in
    under a minute after the repo exists.

    Background task — caller polls ``/status`` for ``mitre`` row.
    """

    async def _run() -> None:
        try:
            await run_parser(
                MitreParser(
                    mode=body.mode,
                    since_days=body.since_days,
                    max_records=body.max_records,
                )
            )
        except Exception:
            log.exception("admin.mitre_backfill_failed")

    background.add_task(_run)
    detail = (
        f"MITRE {body.mode} 백필을 백그라운드에서 시작했습니다. "
        f"진행 상황은 /status 의 mitre 행으로 확인하세요. "
    )
    if body.mode == "full":
        detail += "(첫 실행 시 git clone ~5GB + 340k 행 처리, 30~60분 소요)"
    else:
        detail += f"(최근 {body.since_days}일 델타만 처리)"
    return MitreBackfillResponse(queued=True, mode=body.mode, detail=detail)

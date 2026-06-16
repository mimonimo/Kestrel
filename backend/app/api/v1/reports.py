"""사용자 신고/문의 — 관리자에게 SNS 로 즉시 알림 + 감사 기록.

운영 알림 정책상 시스템 에러 알람은 "지속·반복되는 큰 문제"에서만 울리지만,
사용자가 직접 올린 신고는 누락되면 안 되므로 접수 즉시 알림을 발행한다.

스크린샷(선택)은 SNS 가 바이너리를 못 실으므로, 첨부가 있으면 관리자 이메일로
SES SendRawEmail 첨부 메일을 추가 발송한다(저장소 불필요).
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_optional_user
from app.core.audit import AuditAction, record_audit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.core.rate_limit import enforce_report_rate_limit
from app.core.request_ip import client_ip
from app.models import User
from app.schemas.vulnerability import CamelModel
from app.services.notify import publish_alert

router = APIRouter(prefix="/reports", tags=["reports"])
log = get_logger(__name__)

_CATEGORY_LABELS = {
    "bug": "버그/오류",
    "abuse": "부적절한 콘텐츠",
    "idea": "제안/의견",
    "other": "기타",
}

# 첨부 이미지 제한 — 메일 첨부라 과도한 크기를 막는다.
_MAX_IMAGE_BYTES = 8 * 1024 * 1024  # 8MB
_ALLOWED_IMAGE = {"image/png", "image/jpeg", "image/gif", "image/webp"}
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ReportOut(CamelModel):
    ok: bool
    message: str


@router.post("", response_model=ReportOut, response_model_by_alias=True)
async def submit_report(
    request: Request,
    category: str = Form(default="bug", max_length=32),
    message: str = Form(min_length=5, max_length=2000),
    contact: str = Form(min_length=1, max_length=200),
    url: str | None = Form(default=None, max_length=500),
    image: UploadFile | None = File(default=None),
    me: User | None = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    """신고/문의 접수 → SNS 알림(관리자) + (이미지 있으면) SES 첨부 메일 + 감사 로그.

    연락처는 필수. 이미지는 선택(png/jpeg/gif/webp, 8MB 이하).
    """
    ip = client_ip(request) or "unknown"
    await enforce_report_rate_limit(ip)

    contact = (contact or "").strip()
    if not contact:
        raise HTTPException(400, detail="회신받을 이메일을 입력해 주세요.")
    if not _EMAIL_RE.match(contact):
        raise HTTPException(400, detail="올바른 이메일 형식으로 입력해 주세요.")

    cat = _CATEGORY_LABELS.get(category, category)
    who = f"{me.email} ({me.username})" if me is not None else f"비회원 ({ip})"
    page = url or "-"

    # 이미지(선택) 검증·로드.
    img_bytes: bytes | None = None
    img_name: str | None = None
    img_type: str | None = None
    if image is not None and image.filename:
        ctype = (image.content_type or "").lower()
        if ctype not in _ALLOWED_IMAGE:
            raise HTTPException(400, detail="이미지는 PNG·JPEG·GIF·WEBP 만 첨부할 수 있습니다.")
        img_bytes = await image.read()
        if len(img_bytes) > _MAX_IMAGE_BYTES:
            raise HTTPException(400, detail="이미지는 8MB 이하만 첨부할 수 있습니다.")
        img_name = image.filename[:128]
        img_type = ctype

    subject = f"[Kestrel 신고] {cat}"
    text = (
        f"분류: {cat}\n"
        f"신고자: {who}\n"
        f"회신 연락처: {contact}\n"
        f"페이지: {page}\n"
        f"IP: {ip}\n"
        f"첨부: {'있음(' + (img_name or '') + ')' if img_bytes else '없음'}\n"
        f"────────────\n"
        f"{message}"
    )

    await publish_alert(subject, text)

    # 첨부가 있으면 관리자 이메일로 SES 첨부 메일 추가 발송(SNS 는 바이너리 불가).
    if img_bytes:
        settings = get_settings()
        admin_to = (settings.initial_admin_emails or "").split(",")[0].strip()
        if admin_to:
            try:
                from app.services.email import send_with_attachment

                await send_with_attachment(
                    admin_to,
                    subject,
                    text,
                    attachment=img_bytes,
                    filename=img_name,
                    content_type=img_type,
                )
            except Exception as exc:  # noqa: BLE001 — 첨부 실패가 접수 자체를 막지 않음
                log.warning("report.attach_failed", error=str(exc))
        else:
            log.info("report.attach_skipped_no_admin")

    await record_audit(
        db,
        action=AuditAction.USER_REPORT,
        actor=me,
        actor_label=None if me is not None else "비회원",
        request=request,
        target=cat,
        detail=(f"[첨부] " if img_bytes else "") + message[:470],
    )
    return ReportOut(ok=True, message="신고가 접수되었습니다. 감사합니다.")

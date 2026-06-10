"""이메일 발송 서비스 — AWS SES (회원가입 인증 / 비밀번호 재설정).

설계:
- ``email_enabled=false`` (로컬/개발): 실제 발송 대신 백엔드 로그에 제목 + 링크를
  출력하는 **콘솔 모드**. SES 자격증명 없이도 전체 흐름을 검증할 수 있다.
- ``email_enabled=true`` (운영): boto3 SES ``send_email``. 인스턴스 IAM 역할
  자격증명을 자동 사용(정적 키 불필요). boto3 는 동기라 ``asyncio.to_thread``
  로 이벤트 루프를 막지 않게 감싼다.

보안: 토큰 원문은 링크에만 담기고 로그에는 콘솔 모드에서만(개발 편의) 노출된다.
운영 로그에는 수신자/제목만 남기고 본문/토큰은 남기지 않는다.
"""
from __future__ import annotations

import asyncio
from functools import lru_cache

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


def public_base_url() -> str:
    """이메일 링크용 공개 베이스 URL. public_base_url 우선, 없으면 cors_origins[0]."""
    settings = get_settings()
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    if settings.cors_origins:
        return settings.cors_origins[0].rstrip("/")
    return "http://localhost:3000"


@lru_cache
def _ses_client():  # noqa: ANN202 — boto3 client 타입
    import boto3  # 지연 import — email_enabled=false 면 boto3 미설치여도 동작

    return boto3.client("ses", region_name=get_settings().aws_region)


async def warmup() -> None:
    """앱 시작 시 SES 클라이언트를 미리 초기화 — 첫 메일 발송의 콜드스타트 제거.

    boto3 import + botocore 서비스 모델 로드 + IAM 역할 자격증명(IMDS) 해석 +
    엔드포인트/서명 준비를 한 번에 끝내 둔다(get_send_quota 는 무료·읽기전용).
    이게 없으면 컨테이너 재시작 후 *첫* 발송 요청이 20초 넘게 걸려 사용자가
    멈춤을 겪는다. 비차단(create_task) 으로 호출하므로 부팅/헬스체크를 막지 않는다.
    email_enabled=false(콘솔 모드) 면 아무것도 하지 않는다.
    """
    if not get_settings().email_enabled:
        return
    if (get_settings().email_provider or "ses").lower() != "ses":
        return  # SMTP 등은 SES 워밍업 불필요

    def _init() -> None:
        _ses_client().get_send_quota()

    try:
        await asyncio.to_thread(_init)
        log.info("email.warmup_done")
    except Exception as exc:  # noqa: BLE001 — 워밍업 실패는 발송 자체를 막지 않음
        log.warning("email.warmup_failed", error=str(exc))


def _wrap_html(title: str, intro: str, button_label: str, link: str, footer: str) -> str:
    """간결한 인라인 스타일 HTML 메일 — 메일 클라이언트 호환성 위해 table 기반."""
    return f"""\
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f6f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Apple SD Gothic Neo','Malgun Gothic',sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f6f8;padding:32px 0;">
    <tr><td align="center">
      <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">
        <tr><td style="padding:28px 32px 8px;">
          <div style="font-size:18px;font-weight:700;color:#0f172a;">Kestrel</div>
        </td></tr>
        <tr><td style="padding:8px 32px 0;">
          <h1 style="margin:0 0 12px;font-size:20px;color:#0f172a;">{title}</h1>
          <p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#475569;">{intro}</p>
        </td></tr>
        <tr><td style="padding:0 32px 28px;">
          <a href="{link}" style="display:inline-block;background:#0ea5e9;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 24px;border-radius:9999px;">{button_label}</a>
          <p style="margin:20px 0 0;font-size:12px;line-height:1.6;color:#94a3b8;word-break:break-all;">
            버튼이 동작하지 않으면 아래 주소를 브라우저에 붙여넣으세요:<br>
            <a href="{link}" style="color:#0ea5e9;">{link}</a>
          </p>
        </td></tr>
        <tr><td style="padding:16px 32px;background:#f8fafc;border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:12px;line-height:1.6;color:#94a3b8;">{footer}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


async def _send(to: str, subject: str, html_body: str, text_body: str) -> None:
    """단일 수신자 발송. 콘솔 모드면 로그 출력, 운영이면 SES."""
    settings = get_settings()
    if not settings.email_enabled:
        # 콘솔 모드 — 개발 편의를 위해 본문(텍스트)을 로그에 출력.
        log.info(
            "email.console_mode",
            to=to,
            subject=subject,
            body=text_body,
        )
        return

    from_addr = f"{settings.email_from_name} <{settings.email_from}>"

    # ── SMTP 발송 (Resend 등 외부 서비스) ──────────────────────────
    if (settings.email_provider or "ses").lower() == "smtp":
        def _do_smtp() -> None:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_addr
            msg["To"] = to
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
            host, port = settings.smtp_host, settings.smtp_port
            if settings.smtp_ssl:
                server = smtplib.SMTP_SSL(host, port, timeout=20)
            else:
                server = smtplib.SMTP(host, port, timeout=20)
                server.starttls()
            try:
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.sendmail(settings.email_from, [to], msg.as_string())
            finally:
                server.quit()

        try:
            await asyncio.to_thread(_do_smtp)
            log.info("email.sent", to=to, subject=subject, provider="smtp")
        except Exception as exc:  # noqa: BLE001
            log.error("email.send_failed", to=to, subject=subject, provider="smtp", error=str(exc))
            raise
        return

    def _do_send() -> str:
        resp = _ses_client().send_email(
            Source=from_addr,
            Destination={"ToAddresses": [to]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                    "Text": {"Data": text_body, "Charset": "UTF-8"},
                },
            },
        )
        return resp.get("MessageId", "")

    try:
        message_id = await asyncio.to_thread(_do_send)
        log.info("email.sent", to=to, subject=subject, message_id=message_id)
    except Exception as exc:  # noqa: BLE001 — 발송 실패를 호출자에게 알림
        log.error("email.send_failed", to=to, subject=subject, error=str(exc))
        raise


async def send_verification_email(to: str, token: str) -> None:
    """회원가입 이메일 인증 메일."""
    link = f"{public_base_url()}/verify-email?token={token}"
    ttl_h = get_settings().email_verify_token_ttl_hours
    subject = "[Kestrel] 이메일 인증을 완료해 주세요"
    intro = (
        "Kestrel 회원가입을 환영합니다. 아래 버튼을 눌러 이메일 인증을 완료하면 "
        "로그인할 수 있습니다."
    )
    footer = (
        f"이 링크는 {ttl_h}시간 동안 유효합니다. "
        "본인이 가입한 적이 없다면 이 메일을 무시하셔도 됩니다."
    )
    html = _wrap_html("이메일 인증", intro, "이메일 인증하기", link, footer)
    text = (
        f"Kestrel 이메일 인증\n\n{intro}\n\n{link}\n\n"
        f"이 링크는 {ttl_h}시간 동안 유효합니다."
    )
    await _send(to, subject, html, text)


async def send_password_reset_email(to: str, token: str) -> None:
    """비밀번호 재설정 메일."""
    link = f"{public_base_url()}/reset-password?token={token}"
    ttl_m = get_settings().password_reset_token_ttl_minutes
    subject = "[Kestrel] 비밀번호 재설정 안내"
    intro = (
        "비밀번호 재설정 요청이 접수되었습니다. 아래 버튼을 눌러 새 비밀번호를 "
        "설정하세요. 본인이 요청하지 않았다면 이 메일을 무시하세요."
    )
    footer = (
        f"이 링크는 {ttl_m}분 동안만 유효합니다. 링크가 만료되면 "
        "비밀번호 찾기를 다시 요청해 주세요."
    )
    html = _wrap_html("비밀번호 재설정", intro, "비밀번호 재설정하기", link, footer)
    text = (
        f"Kestrel 비밀번호 재설정\n\n{intro}\n\n{link}\n\n"
        f"이 링크는 {ttl_m}분 동안만 유효합니다."
    )
    await _send(to, subject, html, text)

"""AI lab synthesizer (PR9-D) — build a CVE-specific reproducer from scratch.

For CVEs that vulhub doesn't ship, we ask the configured LLM to produce a
self-contained reproducer:

  * a ``Dockerfile`` (single-stage, debian/python/node base — small, fast)
  * the application files needed to render the vulnerability
  * a single injection point (method/path/parameter/location)
  * a concrete payload that triggers the bug
  * a ``success_indicator`` — a substring that must appear in the response
    body when the bug actually fires

We then build the image, run it once on the isolated sandbox network, send
the synthesized payload, and only on a verified hit do we write the mapping
to ``cve_lab_mappings(kind=synthesized, verified=true)``. Failed verifies
are not cached — the next call retries with a fresh LLM attempt.

This module is intentionally **opt-in via API endpoint**. PR 9-E will wire
the resolver chain to fall back to it automatically.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import CveLabMapping, LabSourceKind, Vulnerability
from app.services.ai_analyzer import call_llm
from app.services.sandbox.catalog import InjectionPoint
from app.services.sandbox.lab_resolver import LabSpec
from app.services.sandbox.manager import (
    SandboxError,
    build_image,
    proxy_request,
    remove_image,
    start_lab,
    stop_lab,
    wait_ready,
)

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class SynthesisResult:
    """Outcome of a single synthesize call.

    On success, ``mapping_id`` is the row that future resolves will hit.
    On failure (build or verify), ``mapping_id`` is None and ``error``
    explains what went wrong; the build artifacts are removed.
    """

    cve_id: str
    image_tag: str
    verified: bool
    mapping_id: int | None
    attempts: int
    error: str | None = None
    spec_dict: dict | None = None
    payload: dict | None = None
    build_log_tail: list[str] = field(default_factory=list)
    response_status: int | None = None
    response_body_preview: str | None = None


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------


_SYSTEM = (
    "당신은 CVE 재현 환경을 자동으로 구축하는 보안 엔지니어 어시스턴트입니다. "
    "주어진 CVE에 대해 (1) 취약한 동작을 그대로 재현하는 최소한의 Dockerfile + 앱 코드를 만들고, "
    "(2) 그 환경에서 실제로 트리거되는 페이로드와 (3) 응답에 반드시 등장하는 성공 지표 문자열을 함께 제출합니다. "
    "이 환경은 외부 인터넷에 접근할 수 없는 격리 네트워크(internal-only bridge) 안에서 root 권한 없이, "
    "메모리 256MB·CPU 0.5 코어 한도로 실행됩니다. 설치/빌드는 60초 이내에 끝나야 합니다. "
    "절대 systemd, supervisor, nginx, mysql 같은 무거운 의존성을 쓰지 마세요. "
    "가능하면 python:3.11-slim + flask 한 파일, 또는 node:20-alpine + express 한 파일 수준으로 끝내세요. "
    "응답은 한국어 키 없이 지정된 JSON 스키마만 반환합니다."
)


_USER_TEMPLATE = """\
## CVE 정보
- CVE ID: {cve_id}
- 제목: {title}
- 설명:
{description}

## 참고 링크 (필요 시 동작 추정에만 사용; 실제 fetch는 하지 말고 알려진 정보만 활용)
{references}

## 출력 형식 (이 JSON 스키마만 반환)
{{
  "description": "짧은 한 문장 — 이 lab이 무엇을 재현하는지",
  "dockerfile": "FROM ...\\n... (작은 단일 스테이지)",
  "files": [
    {{ "path": "app.py", "content": "# 단일 파일로 취약 동작을 그대로 노출하는 최소 앱" }}
  ],
  "container_port": 8080,
  "target_path": "/",
  "injection_point": {{
    "name": "주입 지점 짧은 식별자 (예: 'echo_msg')",
    "method": "GET" | "POST",
    "path": "/...",
    "parameter": "...",
    "location": "query" | "form" | "json" | "header" | "path",
    "response_kind": "html-reflect" | "json-reflect" | "command-exec" | ...,
    "notes": "응답에 어떻게 흔적이 남는지"
  }},
  "payload_example": "위 injection_point에 보낼 실제 값 (이스케이프된 문자열)",
  "success_indicator": "응답 본문에 반드시 등장하는 짧고 고유한 문자열 — payload가 트리거되면 본문에 그대로 나와야 함"
}}

## 매우 중요한 규칙
1. payload_example를 위 injection_point에 그대로 보냈을 때, success_indicator가 응답 본문에 **그대로** 나타나야 합니다.
   예: payload가 `<script>alert('SYN_OK_AB12')</script>` 라면 success_indicator는 `SYN_OK_AB12` (응답 HTML에 그대로 echo).
   예: 명령 인젝션이라면 페이로드가 `; echo SYN_OK_AB12` → 앱이 그 stdout을 응답 본문에 노출.
   외부 호스트로 exfil 같은 건 격리 네트워크라 절대 동작하지 않습니다.
2. 가능한 한 success_indicator는 본 페이로드에 직접 박힌 짧은 토큰(예: "SYN_OK_<랜덤6자>")으로 만드세요.
3. 앱은 반드시 container_port에서 listen해야 합니다. 0.0.0.0 바인딩 필수.
4. 빌드는 30~60초 안에 끝나야 하므로 가벼운 베이스 이미지 + 최소 의존성만 사용하세요.
5. files[].path는 Dockerfile의 COPY 대상과 정확히 일치해야 합니다. 절대경로/상위경로(..) 금지.
"""


# ---------------------------------------------------------------------------
# Schema parsing
# ---------------------------------------------------------------------------


_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\n|\n```$")


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = _FENCE_RE.sub("", t).strip()
    return t


def _references_block(vuln: Vulnerability) -> str:
    if not vuln.references:
        return "(참고 링크 없음 — CVE 설명만 보고 추정해 작성)"
    lines = []
    for r in vuln.references[:8]:
        lines.append(f"- [{r.ref_type.value}] {r.url}")
    return "\n".join(lines)


def _spec_hash(parsed: dict) -> str:
    """Stable hash over the synthesis output. Drives the image tag and the
    ``lab_kind`` field so identical syntheses are idempotent."""
    canon = {
        "dockerfile": parsed.get("dockerfile", ""),
        "files": parsed.get("files", []),
        "container_port": parsed.get("container_port"),
        "target_path": parsed.get("target_path"),
        "injection_point": parsed.get("injection_point", {}),
        "payload_example": parsed.get("payload_example", ""),
        "success_indicator": parsed.get("success_indicator", ""),
    }
    blob = json.dumps(canon, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def _validate_parsed(parsed: dict) -> str | None:
    """Return None if shape is fine, otherwise a short error string."""
    for key in ("dockerfile", "files", "container_port", "target_path", "injection_point", "payload_example", "success_indicator"):
        if key not in parsed:
            return f"필수 필드 누락: {key}"
    if not isinstance(parsed["dockerfile"], str) or not parsed["dockerfile"].strip():
        return "dockerfile 비어 있음"
    if not isinstance(parsed["files"], list):
        return "files는 배열이어야 함"
    for i, f in enumerate(parsed["files"]):
        if not isinstance(f, dict) or "path" not in f or "content" not in f:
            return f"files[{i}] 형식 오류"
        path = str(f["path"])
        if path.startswith("/") or ".." in path.split("/"):
            return f"files[{i}].path 보안 위반: {path}"
    ip = parsed["injection_point"]
    if not isinstance(ip, dict):
        return "injection_point는 객체여야 함"
    for key in ("method", "path", "parameter", "location"):
        if key not in ip:
            return f"injection_point.{key} 누락"
    if not isinstance(parsed["container_port"], int):
        return "container_port는 정수"
    if not isinstance(parsed["success_indicator"], str) or not parsed["success_indicator"].strip():
        return "success_indicator 비어 있음"
    return None


# ---------------------------------------------------------------------------
# Build context staging
# ---------------------------------------------------------------------------


def _build_context_root() -> Path:
    settings = get_settings()
    base = settings.sandbox_syn_build_dir or "/tmp/kestrel-syn-builds"
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _stage_build_context(spec_hash: str, parsed: dict) -> Path:
    """Materialize the Dockerfile + files into a fresh per-hash directory.

    Returns the directory path. Caller is responsible for cleaning up via
    ``_cleanup_build_context`` after the build finishes.
    """
    root = _build_context_root() / spec_hash
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    (root / "Dockerfile").write_text(parsed["dockerfile"], encoding="utf-8")
    for f in parsed["files"]:
        rel = Path(str(f["path"]))
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(str(f["content"]), encoding="utf-8")
    return root


def _cleanup_build_context(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except OSError as e:
        log.debug("synthesizer.cleanup_failed", path=str(path), error=str(e))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _injection_point_from(parsed: dict) -> InjectionPoint:
    ip = parsed["injection_point"]
    return InjectionPoint(
        name=str(ip.get("name", "syn_default")),
        method=str(ip.get("method", "GET")).upper(),
        path=str(ip.get("path", "/")),
        parameter=str(ip.get("parameter", "")),
        location=str(ip.get("location", "query")),
        response_kind=str(ip.get("response_kind", "html-reflect")),
        notes=str(ip.get("notes", "")),
    )


def _spec_dict_for_mapping(parsed: dict, image_tag: str) -> dict:
    """Build the JSONB blob that ``lab_resolver._spec_from_mapping`` reads."""
    ip = _injection_point_from(parsed)
    return {
        "run_kind": "image",
        "description": str(parsed.get("description", "")),
        "image": image_tag,
        "container_port": int(parsed["container_port"]),
        "target_path": str(parsed.get("target_path", "/")),
        "injection_points": [
            {
                "name": ip.name,
                "method": ip.method,
                "path": ip.path,
                "parameter": ip.parameter,
                "location": ip.location,
                "response_kind": ip.response_kind,
                "notes": ip.notes,
            }
        ],
        "build_hint": f"kestrel synthesized — image '{image_tag}' built from cached Dockerfile",
        "success_indicator": str(parsed["success_indicator"]),
    }


def _payload_dict_for_mapping(parsed: dict) -> dict:
    """Pre-fill the cache so adapt_payload can short-circuit on first replay."""
    ip = _injection_point_from(parsed)
    return {
        "method": ip.method,
        "path": ip.path,
        "parameter": ip.parameter,
        "location": ip.location,
        "payload": str(parsed["payload_example"]),
        "success_indicator": str(parsed["success_indicator"]),
        "rationale": "AI 합성 시 검증된 페이로드입니다.",
        "notes": ip.notes,
    }


async def _verify(spec: LabSpec, parsed: dict) -> tuple[bool, dict]:
    """Spawn one ephemeral lab from *spec*, replay payload, check indicator.

    Returns ``(success, exchange)``. The lab is always reaped before return.
    """
    session_id = uuid.uuid4()
    handle = await start_lab(spec, session_id)
    try:
        await wait_ready(handle.target_url, spec)
        ip = _injection_point_from(parsed)
        payload = str(parsed["payload_example"])
        params = data = json_body = headers = None
        if ip.location == "form":
            data = {ip.parameter: payload}
        elif ip.location == "json":
            json_body = {ip.parameter: payload}
        elif ip.location == "header":
            headers = {ip.parameter: payload}
        else:
            params = {ip.parameter: payload}
        exchange = await proxy_request(
            handle.target_url,
            ip.method,
            ip.path,
            params=params,
            data=data,
            json=json_body,
            headers=headers,
        )
    finally:
        try:
            await stop_lab(handle.container_name)
        except Exception as e:  # noqa: BLE001 — best-effort cleanup
            log.warning("synthesizer.stop_failed", error=str(e))

    indicator = str(parsed["success_indicator"])
    body = exchange.get("body") or ""
    return (indicator in body), exchange


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_ATTEMPT_COOLDOWN = timedelta(hours=24)


async def synthesize(
    db: AsyncSession,
    vuln: Vulnerability,
    *,
    force_regenerate: bool = False,
) -> SynthesisResult:
    """End-to-end: prompt → parse → build → verify → cache (on success).

    Rate limiting:
      * If a verified ``synthesized`` mapping exists, return it without
        spending tokens (unless ``force_regenerate``).
      * If a *failed* attempt row exists and is younger than 24h, refuse
        the call with a rate-limit error so persistently-broken CVEs don't
        burn tokens on repeat (unless ``force_regenerate``).
      * Every attempt — success or failure — stamps
        ``last_synthesis_attempt_at`` on the row, so the cooldown survives
        process restarts.
    """
    settings = get_settings()
    cve_id = vuln.cve_id
    now = datetime.now(timezone.utc)

    existing = await db.scalar(
        select(CveLabMapping).where(
            CveLabMapping.cve_id == cve_id,
            CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
        )
    )

    if existing is not None and existing.verified and not force_regenerate:
        return SynthesisResult(
            cve_id=cve_id,
            image_tag=str((existing.spec or {}).get("image", "")),
            verified=True,
            mapping_id=existing.id,
            attempts=0,
            spec_dict=existing.spec or {},
            payload=existing.known_good_payload,
        )

    if (
        existing is not None
        and not existing.verified
        and not force_regenerate
        and existing.last_synthesis_attempt_at is not None
    ):
        age = now - existing.last_synthesis_attempt_at
        if age < _ATTEMPT_COOLDOWN:
            remaining = _ATTEMPT_COOLDOWN - age
            hours = int(remaining.total_seconds() // 3600) + 1
            return SynthesisResult(
                cve_id=cve_id,
                image_tag="",
                verified=False,
                mapping_id=existing.id,
                attempts=0,
                error=(
                    f"이 CVE 는 최근 24시간 내에 합성에 실패했습니다 — "
                    f"약 {hours}시간 후 재시도 가능합니다 "
                    "(즉시 재시도하려면 forceRegenerate=true)."
                ),
            )

    # Stamp the attempt start so concurrent calls / process restarts respect
    # the cooldown even before the LLM returns.
    if existing is None:
        attempt_row = CveLabMapping(
            cve_id=cve_id,
            kind=LabSourceKind.SYNTHESIZED,
            lab_kind=f"synthesized/{cve_id}/pending",
            spec={},
            verified=False,
            last_synthesis_attempt_at=now,
            notes="합성 시도 진행 중...",
        )
        db.add(attempt_row)
        await db.flush()
        attempt_mapping_id = attempt_row.id
    else:
        existing.last_synthesis_attempt_at = now
        attempt_mapping_id = existing.id
    await db.commit()

    user_prompt = _USER_TEMPLATE.format(
        cve_id=cve_id,
        title=vuln.title,
        description=vuln.description,
        references=_references_block(vuln),
    )

    last_error: str | None = None
    last_logs: list[str] = []
    attempts = 0
    max_attempts = max(1, int(settings.sandbox_syn_max_attempts))

    while attempts < max_attempts:
        attempts += 1
        try:
            raw = await call_llm(db, _SYSTEM, user_prompt, force_json=True)
        except Exception as e:  # noqa: BLE001 — surface upstream as result
            last_error = f"LLM 호출 실패: {e}"
            log.warning("synthesizer.llm_failed", cve_id=cve_id, error=last_error)
            continue
        try:
            parsed = json.loads(_strip_fence(raw))
        except json.JSONDecodeError as e:
            last_error = f"AI 응답 JSON 파싱 실패: {e}"
            log.warning("synthesizer.parse_failed", cve_id=cve_id, raw=raw[:300])
            continue

        validation_err = _validate_parsed(parsed)
        if validation_err is not None:
            last_error = f"응답 스키마 검증 실패: {validation_err}"
            log.warning("synthesizer.schema_invalid", cve_id=cve_id, error=validation_err)
            continue

        sha = _spec_hash(parsed)
        image_tag = f"{settings.sandbox_syn_image_prefix}-{sha}:latest"
        ctx_dir = _stage_build_context(sha, parsed)

        try:
            try:
                logs = await build_image(
                    context_dir=str(ctx_dir),
                    tag=image_tag,
                    timeout_seconds=settings.sandbox_syn_build_timeout_seconds,
                )
                last_logs = logs[-30:]
            except SandboxError as e:
                last_error = f"이미지 빌드 실패: {e}"
                last_logs = []
                log.warning("synthesizer.build_failed", cve_id=cve_id, error=str(e))
                continue

            spec_dict = _spec_dict_for_mapping(parsed, image_tag)
            spec = LabSpec(
                run_kind="image",
                lab_kind=f"synthesized/{cve_id}/{sha}",
                description=spec_dict["description"],
                container_port=spec_dict["container_port"],
                target_path=spec_dict["target_path"],
                injection_points=[_injection_point_from(parsed)],
                image=image_tag,
                build_hint=spec_dict["build_hint"],
            )

            try:
                ok, exchange = await _verify(spec, parsed)
            except SandboxError as e:
                last_error = f"검증 단계 실패: {e}"
                log.warning("synthesizer.verify_failed", cve_id=cve_id, error=str(e))
                await remove_image(image_tag)
                continue

            body_preview = (exchange.get("body") or "")[:400]
            status_code = exchange.get("status_code")

            if not ok:
                last_error = (
                    f"success_indicator '{parsed['success_indicator']}'가 응답 본문에 없음 "
                    f"(status={status_code})"
                )
                log.info(
                    "synthesizer.indicator_missing",
                    cve_id=cve_id,
                    status=status_code,
                    body_head=body_preview[:120],
                )
                await remove_image(image_tag)
                continue

            payload_dict = _payload_dict_for_mapping(parsed)
            mapping = await db.get(CveLabMapping, attempt_mapping_id)
            if mapping is None:
                # Should never happen — we just inserted it. Fall back to a
                # fresh insert so the result is still cached.
                mapping = CveLabMapping(
                    cve_id=cve_id,
                    kind=LabSourceKind.SYNTHESIZED,
                    lab_kind=spec.lab_kind,
                    spec=spec_dict,
                    known_good_payload=payload_dict,
                    verified=True,
                    last_verified_at=datetime.now(timezone.utc),
                    notes=f"AI 합성, attempts={attempts}, sha={sha}",
                )
                db.add(mapping)
            else:
                mapping.lab_kind = spec.lab_kind
                mapping.spec = spec_dict
                mapping.known_good_payload = payload_dict
                mapping.verified = True
                mapping.last_verified_at = datetime.now(timezone.utc)
                mapping.notes = f"AI 합성, attempts={attempts}, sha={sha}"
            await db.flush()
            await db.commit()
            log.info(
                "synthesizer.cached",
                cve_id=cve_id,
                mapping_id=mapping.id,
                image=image_tag,
            )
            return SynthesisResult(
                cve_id=cve_id,
                image_tag=image_tag,
                verified=True,
                mapping_id=mapping.id,
                attempts=attempts,
                spec_dict=spec_dict,
                payload=payload_dict,
                build_log_tail=last_logs,
                response_status=status_code,
                response_body_preview=body_preview,
            )
        finally:
            _cleanup_build_context(ctx_dir)

    # Every attempt failed — leave the attempt row with verified=False and
    # the cooldown stamp so the next caller is rate-limited. Drop a brief
    # note so operators can see why the row exists.
    failure_note = (
        f"AI 합성 시도 실패, attempts={attempts}, "
        f"마지막 오류: {(last_error or '')[:240]}"
    )
    failure_row = await db.get(CveLabMapping, attempt_mapping_id)
    if failure_row is not None:
        failure_row.notes = failure_note
        await db.commit()
    return SynthesisResult(
        cve_id=cve_id,
        image_tag="",
        verified=False,
        mapping_id=attempt_mapping_id,
        attempts=attempts,
        error=last_error or "알 수 없는 실패",
        build_log_tail=last_logs,
    )

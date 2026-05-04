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
from typing import Awaitable, Callable

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import CveLabFeedback, CveLabMapping, LabSourceKind, Vulnerability
from app.services.ai_analyzer import call_llm
from app.services.sandbox.catalog import InjectionPoint
from app.services.sandbox.lab_resolver import (
    LabSpec,
    is_degraded,
    list_synthesized_candidates,
)

# Soft cap on simultaneous verified synthesized candidates per CVE. Above
# this we trim the *lowest-scoring* row (degraded/older first) so disk +
# image cache don't grow unbounded as users regenerate. Lower than this
# defeats best-of-N's premise; higher and the cache panel/UI gets noisy.
_BEST_OF_N_CAP = 3
from app.services.sandbox.manager import (
    SandboxError,
    build_image,
    proxy_request,
    remove_image,
    start_lab,
    stop_lab,
    wait_ready,
)
from app.services.sandbox.synthesizer_gc import gc_synthesized_images
from app.services.sandbox.synthesizer_probes import (
    ProbeOutcome,
    VerificationVerdict,
    build_verdict,
    known_kinds,
    select_probes,
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
{prior_attempts}

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
    "name": "주입 지점 짧은 식별자 (예: 'cmd_param')",
    "method": "GET" | "POST",
    "path": "/...",
    "parameter": "...",
    "location": "query" | "form" | "json" | "header" | "path",
    "response_kind": "<아래 known_kinds 중 하나 — CVE 의 실제 취약점 클래스에 맞춰 선택>",
    "notes": "응답에 어떻게 흔적이 남는지"
  }},
  "payload_example": "위 injection_point에 보낼 실제 값 (이스케이프된 문자열)",
  "success_indicator": "응답 본문에 반드시 등장하는 짧고 고유한 문자열 — payload가 트리거되면 본문에 그대로 나와야 함"
}}

## response_kind 선택 가이드 — CVE 의 실제 취약점 클래스에 맞춰 고르세요

다음 응답 클래스만 backend probe 가 ground-truth 로 검증합니다 (그 외 값은 약식 검증으로 통과되어 신뢰도 낮음 표시):

  * **command-exec / rce** — 입력 문자열이 셸/exec 컨텍스트에서 실행되어 시스템 명령 출력이 응답에 나옴
  * **path-traversal / lfi** — 입력이 파일 경로로 사용되어 임의 파일 내용이 응답에 나옴
  * **ssti / template-injection** — 입력이 템플릿 엔진에 평가되어 식의 결과(예: 7*7=49)가 응답에 나옴
  * **html-reflect / json-reflect** — XSS 류, 입력이 응답 본문에 escape 없이 그대로 박힘
  * **sqli** — 입력이 SQL 쿼리에 합쳐져 동작 (특히 time-based: `' OR SLEEP(5) --` 류로 응답이 지연됨)
  * **xxe** — 입력이 XML parser 에 들어가 외부 엔티티가 평가되어 파일 내용이 응답에 나옴
  * **open-redirect** — 입력 URL 이 그대로 Location 헤더에 들어가 3xx redirect 가 일어남
  * **deserialization / pickle** — base64 pickle 페이로드가 deserialize 되어 임의 코드 실행
  * **ssrf / url-fetch** — 입력 URL 을 lab 이 실제로 outbound HTTP 요청으로 fetch

가장 흔한 실수: 모든 CVE 를 html-reflect (XSS) 로 만드는 것. 원본 CVE 가 RCE / SQLi / SSRF / path-traversal 이라면
**그 클래스 그대로** 재현하세요 — XSS 로 환원하면 backend probe 가 다른 probe 를 적용해 reject 하고 사용자에게는
다른 lab 이 노출되지 않습니다. CVE 가 명백한 XSS 일 때만 html-reflect 를 고르세요.

## 매우 중요한 규칙
1. payload_example를 위 injection_point에 그대로 보냈을 때, success_indicator가 응답 본문(또는 side-channel — RCE/path-trav/XXE
   라면 명령 출력 / 파일 내용 / 평가 결과)에 **그대로** 나타나야 합니다.
   예 (command-exec): payload `; echo SYN_OK_AB12` → success_indicator `SYN_OK_AB12` (앱이 stdout 을 응답에 노출)
   예 (path-traversal): payload `../../etc/passwd` → success_indicator `root:x:` (passwd 파일의 알려진 토큰)
   예 (ssti, jinja2): payload `{{{{7*7}}}}` → success_indicator `49`
   예 (html-reflect): payload `<x>SYN_OK_AB12</x>` → success_indicator `SYN_OK_AB12`
   외부 호스트로 exfil 같은 건 격리 네트워크라 절대 동작하지 않습니다.
2. success_indicator 는 짧고 고유한 토큰이거나 (예: `SYN_OK_<랜덤6자>`), 클래스 고유의 결정적 출력
   (예: SSTI 의 `49`, path-traversal 의 `root:x:`) 이어야 합니다.
   단, success_indicator 가 files 본문에 그대로 들어 있으면 echo trap 으로 거부됩니다 —
   페이로드 또는 backend 가 만든 input 을 통해서만 응답에 도달해야 합니다.
3. 앱은 반드시 container_port에서 listen해야 합니다. 0.0.0.0 바인딩 필수.
4. 빌드는 30~60초 안에 끝나야 하므로 가벼운 베이스 이미지 + 최소 의존성만 사용하세요.
5. files[].path는 Dockerfile의 COPY 대상과 정확히 일치해야 합니다. 절대경로/상위경로(..) 금지.
6. response_kind 는 위 가이드 중 정확히 하나의 alias 를 (전체 허용 목록: {known_kinds}).
7. lab 은 단순히 입력을 그대로 echo 하기만 하는 형태(echo machine)면 backend probe 가 reject 합니다 —
   실제 CVE 동작(명령 실행, 템플릿 평가, 파일 읽기, time-based SQLi, 외부 fetch 등)을 그대로 재현해야 합니다.
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


async def _prior_attempts_block(
    db: AsyncSession, existing: CveLabMapping | None
) -> str:
    """Build the "previous attempt — avoid this approach" prompt section.

    Pulled from the existing synthesized mapping (if any). Self-refinement
    loop (PR9-K): when the user explicitly retries a previously-attempted
    CVE, hand the LLM a compact summary of *what didn't work* so it can
    pick a different approach instead of regenerating the same broken lab.

    Returns an empty string when there's nothing to feed back — the caller
    omits the section entirely so first-time attempts get the original
    prompt verbatim.
    """
    if existing is None:
        return ""

    spec = existing.spec or {}
    payload = existing.known_good_payload or {}
    ip_list = spec.get("injection_points") or []
    ip = ip_list[0] if ip_list else {}

    base = _base_image(str(spec.get("dockerfile") or payload.get("dockerfile") or ""))
    # Spec rows don't carry the Dockerfile (we only persist the runnable
    # image tag). Use the recorded image as the rough base reference.
    if base == "(unknown)":
        base = str(spec.get("image") or "(unknown)")

    summary_lines: list[str] = ["## 이전 시도 (피해야 할 접근)"]
    summary_lines.append(
        f"- 베이스 이미지: {base}"
    )
    if ip:
        summary_lines.append(
            f"- 주입 지점: {ip.get('method', '?')} {ip.get('path', '?')} "
            f"({ip.get('location', '?')}:{ip.get('parameter', '?')}) "
            f"→ {ip.get('response_kind', '?')}"
        )
    if payload.get("payload"):
        summary_lines.append(f"- 사용한 페이로드 예: {str(payload['payload'])[:200]}")
    if payload.get("success_indicator"):
        summary_lines.append(
            f"- success_indicator: {payload['success_indicator']}"
        )

    if existing.verified and is_degraded(existing):
        summary_lines.append(
            f"- 결과: 검증은 통과했으나 사용자 평가로 격하됨 "
            f"(👍 {existing.feedback_up} / 👎 {existing.feedback_down}) — "
            "응답 본문에 indicator는 보이지만 실제 CVE 동작과 다른 lab일 가능성이 큼"
        )
    elif not existing.verified:
        summary_lines.append(
            f"- 결과: 합성 실패. 마지막 노트: {(existing.notes or '(노트 없음)')[:240]}"
        )

    verification = spec.get("verification") or {}
    if verification:
        method = verification.get("method") or "(unknown)"
        summary_lines.append(f"- 이전 검증 method: {method}")
        if verification.get("rejection_reason"):
            summary_lines.append(
                f"  · 거부 사유: {str(verification['rejection_reason'])[:300]}"
            )
        for probe in (verification.get("probes") or [])[:5]:
            mark = "PASS" if probe.get("passed") else "FAIL"
            summary_lines.append(
                f"  · probe[{probe.get('name')}] {mark} — {str(probe.get('rationale') or '')[:240]}"
            )

    # Pull a few down-vote notes so the LLM sees the human reasoning.
    notes = (
        await db.execute(
            select(CveLabFeedback.note)
            .where(
                CveLabFeedback.mapping_id == existing.id,
                CveLabFeedback.vote == "down",
                CveLabFeedback.note.isnot(None),
            )
            .limit(5)
        )
    ).scalars().all()
    notes = [n.strip() for n in notes if n and n.strip()]
    if notes:
        summary_lines.append("- 사용자 👎 노트:")
        for n in notes:
            summary_lines.append(f"  · {n[:240]}")

    summary_lines.append("")
    summary_lines.append(
        "**위 접근(베이스/주입 지점/페이로드 형태)은 이미 실패 또는 격하된 시도이므로 그대로 반복하지 마세요. "
        "다른 베이스 이미지, 다른 엔드포인트, 다른 location, 또는 아예 다른 취약 동작 클래스(예: SSTI 대신 path traversal, "
        "reflect 대신 stored)로 시도하세요.**"
    )
    return "\n".join(summary_lines)


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
    """Return None if shape is fine, otherwise a short error string.

    Beyond shape, this gate rejects shapes that are *structurally* set up
    to pass verification trivially:
      * indicator shorter than 8 chars (collision-prone)
      * indicator equal to payload (closed echo loop)
      * indicator literally present in any file the LLM emitted (the lab
        can return it without ever evaluating the payload — classic echo
        trap), and
      * missing/empty ``response_kind`` (backend probes need it to pick
        the right probe class).
    """
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
    response_kind = str(ip.get("response_kind") or "").strip()
    if not response_kind:
        return "injection_point.response_kind 누락 — 어떤 종류의 취약점인지 명시 필요"
    if not isinstance(parsed["container_port"], int):
        return "container_port는 정수"
    if not isinstance(parsed["success_indicator"], str) or not parsed["success_indicator"].strip():
        return "success_indicator 비어 있음"
    indicator = parsed["success_indicator"].strip()
    if len(indicator) < 8:
        return f"success_indicator 가 너무 짧음 (len={len(indicator)}, 최소 8자) — 우연 일치 가능성"
    payload_example = str(parsed.get("payload_example") or "").strip()
    if indicator == payload_example:
        return "success_indicator 가 payload_example 와 동일 — 단순 echo 검증이라 의미 없음"
    for i, f in enumerate(parsed["files"]):
        content = str(f.get("content") or "")
        if indicator in content:
            return (
                f"success_indicator '{indicator}' 가 files[{i}] ({f.get('path')}) 본문에 포함됨 — "
                "lab 이 payload 와 무관하게 indicator 를 노출하는 echo trap"
            )
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
    # response_kind 는 _validate_parsed 가 위에서 비어있으면 reject 했기에
    # 여기서 기본값을 채우지 않는다. 옛 코드는 "html-reflect" 로 폴백해 모든
    # 미선언 lab 이 자동으로 XSS 가 됐었음 — 그게 클래스 편향의 일부였다.
    response_kind = str(ip.get("response_kind") or "").strip()
    return InjectionPoint(
        name=str(ip.get("name", "syn_default")),
        method=str(ip.get("method", "GET")).upper(),
        path=str(ip.get("path", "/")),
        parameter=str(ip.get("parameter", "")),
        location=str(ip.get("location", "query")),
        response_kind=response_kind,
        notes=str(ip.get("notes", "")),
    )


_BASE_IMAGE_RE = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)


def _base_image(dockerfile: str) -> str:
    """Pull the first ``FROM <image>`` out of the Dockerfile for the digest."""
    m = _BASE_IMAGE_RE.search(dockerfile or "")
    return m.group(1) if m else "(unknown)"


def _build_digest(parsed: dict, *, attempts: int, sha: str) -> str:
    """Human-readable one-liner describing this synthesized lab.

    Surfaced on the CVE detail sidebar so a user picking between the
    "vulhub vs synthesized" badges has some idea *what* the AI built —
    base image, injection shape, response kind. Pure formatting, no I/O.
    """
    ip = _injection_point_from(parsed)
    base = _base_image(parsed.get("dockerfile", ""))
    return (
        f"AI 합성 — {base} 베이스, "
        f"{ip.method} {ip.path} 의 {ip.location}:{ip.parameter} 에 "
        f"{ip.response_kind} 페이로드 주입 "
        f"(attempts={attempts}, sha={sha})"
    )


def _spec_dict_for_mapping(parsed: dict, image_tag: str, *, digest: str = "") -> dict:
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
        "digest": digest,
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


def _verification_dict(verdict: VerificationVerdict) -> dict:
    """Serialize the verdict for persistence inside spec/notes JSONB.

    Stored verbatim on the mapping so PR9-K's ``_prior_attempts_block``
    can surface concrete probe rationales on the next retry instead of
    having to re-derive them. Evidence is JSON-friendly by construction
    (probes only stash dict/str/int/float into ``ProbeOutcome.evidence``).
    """
    return {
        "method": verdict.method,
        "passed": verdict.passed,
        "rejection_reason": verdict.rejection_reason,
        "probes": [
            {
                "name": r.name,
                "kind": r.kind,
                "passed": r.passed,
                "rationale": r.rationale,
                "evidence": r.evidence,
            }
            for r in verdict.probe_results
        ],
    }


async def _verify(spec: LabSpec, parsed: dict) -> tuple[VerificationVerdict, dict]:
    """Spawn one ephemeral lab, run backend probes + legacy check.

    Returns ``(verdict, exchange)``. The lab is always reaped before
    return. The exchange is the legacy LLM-payload roundtrip kept around
    for the UI; it is **not** the truth signal anymore. The truth signal
    is ``verdict.passed`` from ``synthesizer_probes.build_verdict``.

    Why we still run the legacy check: when a lab declares a
    ``response_kind`` the probe registry doesn't recognise yet, we need
    *something* to gate on. ``build_verdict`` will use the legacy result
    only as a last-resort fallback (``method=llm_indicator_only``) and
    log a warning — operators should add a probe class for that kind.
    """
    session_id = uuid.uuid4()
    handle = await start_lab(spec, session_id)
    try:
        await wait_ready(handle.target_url, spec)
        ip = _injection_point_from(parsed)

        # Legacy LLM-payload check — captured for UI display + fallback.
        payload = str(parsed["payload_example"])
        params = data = json_body = headers = None
        loc = (ip.location or "query").lower()
        if loc == "form":
            data = {ip.parameter: payload}
        elif loc == "json":
            json_body = {ip.parameter: payload}
        elif loc == "header":
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
        indicator = str(parsed["success_indicator"])
        legacy_passed = indicator in (exchange.get("body") or "")

        # Backend-built probes own the truth signal.
        probes = select_probes(ip.response_kind)
        probe_results: list[ProbeOutcome] = []
        for probe in probes:
            try:
                outcome = await probe.run(handle=handle, ip=ip)
            except Exception as e:  # noqa: BLE001 — one failing probe shouldn't halt the rest
                log.warning(
                    "synthesizer.probe_exception",
                    probe=probe.name,
                    error=str(e),
                )
                outcome = ProbeOutcome(
                    name=probe.name,
                    kind=str(probe.applies_to[0] if probe.applies_to else "unknown"),
                    passed=False,
                    rationale=f"probe 실행 중 예외: {e}",
                    evidence={"exception": str(e)},
                )
            probe_results.append(outcome)

        verdict = build_verdict(
            ip.response_kind,
            probe_results,
            fallback_passed=legacy_passed,
        )
    finally:
        try:
            await stop_lab(handle.container_name)
        except Exception as e:  # noqa: BLE001 — best-effort cleanup
            log.warning("synthesizer.stop_failed", error=str(e))

    return verdict, exchange


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_ATTEMPT_COOLDOWN = timedelta(hours=24)


# Progress callback signature: ``await cb(phase, message, payload)``.
# Phases (UI consumption — keep stable):
#   start           — synthesis kicked off (cooldown not yet checked)
#   cached_hit      — verified mapping exists, returning early (terminal)
#   cooldown        — recent failure within 24h, refusing (terminal)
#   call_llm        — about to call LLM
#   parsed          — JSON parsed + schema validated
#   build_started   — docker build kicked off
#   build_done      — image built (payload.size_mb on success)
#   lab_started     — verification container running
#   verifying       — sending verification payload
#   verify_failed   — indicator missing in response (will retry or fail)
#   verify_ok       — indicator found, about to cache
#   cached          — final success (terminal)
#   failed          — all attempts exhausted (terminal)
ProgressCallback = Callable[[str, str, dict | None], Awaitable[None]]


async def _noop_progress(phase: str, message: str, payload: dict | None) -> None:
    return None


async def synthesize(
    db: AsyncSession,
    vuln: Vulnerability,
    *,
    force_regenerate: bool = False,
    progress: ProgressCallback | None = None,
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
    emit: ProgressCallback = progress or _noop_progress
    await emit("start", f"{cve_id} 합성 준비 중", {"cveId": cve_id})

    # Opportunistic LRU sweep — keeps the synthesized-image cache under the
    # configured ceilings without a separate cron. Failures never block
    # synthesis; if docker is unreachable we'd fail at build_image anyway.
    try:
        await gc_synthesized_images(db)
    except Exception as e:  # noqa: BLE001 — best-effort housekeeping
        log.warning("synthesizer.gc_failed", error=str(e))

    # Best-of-N: there may be multiple synthesized rows per CVE — one
    # cooldown placeholder (lab_kind="synthesized/<cve>/pending") plus up
    # to ``_BEST_OF_N_CAP`` verified candidates with hash-suffixed
    # lab_kinds. The cached-hit / degraded / cooldown logic below cares
    # about *one* row each, so we project the multi-row state down to
    # those two pointers.
    candidates = await list_synthesized_candidates(db, cve_id)
    placeholder_kind = f"synthesized/{cve_id}/pending"
    placeholder = next(
        (m for m in candidates if m.lab_kind == placeholder_kind), None
    )
    verified_candidates = [m for m in candidates if m.verified]
    # The "best" verified candidate per the resolver's score order. Used
    # below for the cached-hit shortcut and cooldown timestamp lookup so
    # the synthesizer behavior matches what resolve_lab() would pick.
    existing = verified_candidates[0] if verified_candidates else placeholder

    # Cached-hit shortcut. Skip when:
    #   - caller asked to regenerate, OR
    #   - the existing mapping was demoted by user feedback (PR9-J) — returning
    #     it would just hand back the same broken lab the user tried to retire.
    #     Treating degraded the same as not-verified means a consented retry
    #     spends LLM tokens on a fresh attempt, which is what the user clicked.
    existing_degraded = existing is not None and is_degraded(existing)
    if (
        existing is not None
        and existing.verified
        and not force_regenerate
        and not existing_degraded
    ):
        await emit(
            "cached_hit",
            "이미 검증된 합성 이미지가 있습니다 — 재사용",
            {"mappingId": existing.id},
        )
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
            cooldown_msg = (
                f"이 CVE 는 최근 24시간 내에 합성에 실패했습니다 — "
                f"약 {hours}시간 후 재시도 가능합니다 "
                "(즉시 재시도하려면 forceRegenerate=true)."
            )
            await emit("cooldown", cooldown_msg, {"hoursRemaining": hours})
            return SynthesisResult(
                cve_id=cve_id,
                image_tag="",
                verified=False,
                mapping_id=existing.id,
                attempts=0,
                error=cooldown_msg,
            )

    # Stamp the attempt start on the cooldown placeholder so concurrent
    # calls / process restarts respect the 24h rate limit even before the
    # LLM returns. The placeholder is shared across all candidates of a
    # CVE — we never insert a second one and never roll it into a verified
    # candidate.
    if placeholder is None:
        attempt_row = CveLabMapping(
            cve_id=cve_id,
            kind=LabSourceKind.SYNTHESIZED,
            lab_kind=placeholder_kind,
            spec={},
            verified=False,
            last_synthesis_attempt_at=now,
            notes="합성 시도 진행 중...",
        )
        db.add(attempt_row)
        await db.flush()
        attempt_mapping_id = attempt_row.id
    else:
        placeholder.last_synthesis_attempt_at = now
        attempt_mapping_id = placeholder.id
    await db.commit()

    prior_block = await _prior_attempts_block(db, existing)
    if prior_block:
        log.info(
            "synthesizer.prior_context_injected",
            cve_id=cve_id,
            mapping_id=existing.id if existing else None,
            length=len(prior_block),
        )
    user_prompt = _USER_TEMPLATE.format(
        cve_id=cve_id,
        title=vuln.title,
        description=vuln.description,
        references=_references_block(vuln),
        prior_attempts=("\n" + prior_block) if prior_block else "",
        known_kinds=", ".join(sorted(set(known_kinds()))),
    )

    last_error: str | None = None
    last_logs: list[str] = []
    attempts = 0
    max_attempts = max(1, int(settings.sandbox_syn_max_attempts))

    while attempts < max_attempts:
        attempts += 1
        await emit("call_llm", f"LLM 호출 (시도 {attempts}/{max_attempts})", {"attempt": attempts})
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
        await emit(
            "parsed",
            "AI 응답 파싱 + 스키마 검증 완료",
            {"files": len(parsed.get("files") or [])},
        )

        sha = _spec_hash(parsed)
        image_tag = f"{settings.sandbox_syn_image_prefix}-{sha}:latest"
        ctx_dir = _stage_build_context(sha, parsed)

        try:
            await emit("build_started", f"docker 이미지 빌드 중 ({image_tag})", {"imageTag": image_tag})
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
            await emit("build_done", "이미지 빌드 완료", {"imageTag": image_tag})

            digest = _build_digest(parsed, attempts=attempts, sha=sha)
            spec_dict = _spec_dict_for_mapping(parsed, image_tag, digest=digest)
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

            await emit("lab_started", "검증용 컨테이너 기동 + backend probe 실행", None)
            try:
                verdict, exchange = await _verify(spec, parsed)
            except SandboxError as e:
                last_error = f"검증 단계 실패: {e}"
                log.warning("synthesizer.verify_failed", cve_id=cve_id, error=str(e))
                await remove_image(image_tag)
                continue

            body_preview = (exchange.get("body") or "")[:400]
            status_code = exchange.get("status_code")
            verification = _verification_dict(verdict)
            spec_dict["verification"] = verification

            if not verdict.passed:
                last_error = (
                    f"검증 실패 (method={verdict.method}): "
                    f"{verdict.rejection_reason or '(사유 없음)'}"
                )
                log.info(
                    "synthesizer.verify_rejected",
                    cve_id=cve_id,
                    method=verdict.method,
                    status=status_code,
                    probe_count=len(verdict.probe_results),
                )
                await emit(
                    "verify_failed",
                    last_error,
                    {
                        "status": status_code,
                        "bodyPreview": body_preview[:200],
                        "method": verdict.method,
                        "probes": [
                            {"name": r.name, "passed": r.passed, "rationale": r.rationale}
                            for r in verdict.probe_results
                        ],
                    },
                )
                await remove_image(image_tag)
                continue
            await emit(
                "verify_ok",
                f"검증 통과 (method={verdict.method})",
                {
                    "status": status_code,
                    "method": verdict.method,
                    "probes": [
                        {"name": r.name, "passed": r.passed, "rationale": r.rationale}
                        for r in verdict.probe_results
                    ],
                },
            )

            if verdict.method == "llm_indicator_only":
                digest = (
                    digest
                    + " — ⚠️ backend probe 미적용 (response_kind 미인식), "
                    "LLM-indicator-only 약식 검증"
                )
                spec_dict["digest"] = digest

            payload_dict = _payload_dict_for_mapping(parsed)
            # Best-of-N (PR 9-S): always INSERT a fresh row for the
            # verified candidate; the placeholder stays around to track
            # the next cooldown window. If a row with this exact lab_kind
            # already exists (synthesizer is deterministic on identical
            # spec hashes), upsert it in place and reset its feedback so
            # the resurrected mapping starts with a clean reputation.
            existing_same_sha = await db.scalar(
                select(CveLabMapping).where(
                    CveLabMapping.cve_id == cve_id,
                    CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
                    CveLabMapping.lab_kind == spec.lab_kind,
                )
            )
            if existing_same_sha is None:
                mapping = CveLabMapping(
                    cve_id=cve_id,
                    kind=LabSourceKind.SYNTHESIZED,
                    lab_kind=spec.lab_kind,
                    spec=spec_dict,
                    known_good_payload=payload_dict,
                    verified=True,
                    last_verified_at=datetime.now(timezone.utc),
                    notes=digest,
                )
                db.add(mapping)
            else:
                stale_feedback_purged = await db.execute(
                    delete(CveLabFeedback).where(
                        CveLabFeedback.mapping_id == existing_same_sha.id
                    )
                )
                if stale_feedback_purged.rowcount:
                    log.info(
                        "synthesizer.feedback_reset",
                        cve_id=cve_id,
                        mapping_id=existing_same_sha.id,
                        purged=int(stale_feedback_purged.rowcount),
                    )
                existing_same_sha.spec = spec_dict
                existing_same_sha.known_good_payload = payload_dict
                existing_same_sha.verified = True
                existing_same_sha.last_verified_at = datetime.now(timezone.utc)
                existing_same_sha.notes = digest
                existing_same_sha.feedback_up = 0
                existing_same_sha.feedback_down = 0
                mapping = existing_same_sha
            await db.flush()
            # Trim to ``_BEST_OF_N_CAP`` — drop the lowest-scoring verified
            # candidates first (degraded > older > lower-id). The fresh
            # row we just inserted ranks highest by recency so it survives.
            verified_now = (
                await db.scalars(
                    select(CveLabMapping).where(
                        CveLabMapping.cve_id == cve_id,
                        CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
                        CveLabMapping.verified.is_(True),
                    )
                )
            ).all()
            if len(verified_now) > _BEST_OF_N_CAP:
                # Same scoring as resolver / list_synthesized_candidates.
                def _score(m: CveLabMapping) -> tuple:
                    if m.verified and not is_degraded(m):
                        tier = 3
                    elif m.verified:
                        tier = 2
                    elif is_degraded(m):
                        tier = 0
                    else:
                        tier = 1
                    bal = int(m.feedback_up or 0) - int(m.feedback_down or 0)
                    rec = m.last_verified_at or m.updated_at
                    return (tier, bal, rec, m.id)

                ordered = sorted(verified_now, key=_score, reverse=True)
                trim = ordered[_BEST_OF_N_CAP:]
                for victim in trim:
                    log.info(
                        "synthesizer.candidate_trimmed",
                        cve_id=cve_id,
                        victim_mapping_id=victim.id,
                        victim_lab_kind=victim.lab_kind,
                        kept=[m.id for m in ordered[:_BEST_OF_N_CAP]],
                    )
                    await db.delete(victim)
            await db.commit()
            log.info(
                "synthesizer.cached",
                cve_id=cve_id,
                mapping_id=mapping.id,
                image=image_tag,
            )
            await emit(
                "cached",
                "매핑 row 저장 — 이후 호출은 캐시 사용",
                {"mappingId": mapping.id, "imageTag": image_tag, "digest": digest},
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
    final_error = last_error or "알 수 없는 실패"
    await emit("failed", final_error, {"attempts": attempts})
    return SynthesisResult(
        cve_id=cve_id,
        image_tag="",
        verified=False,
        mapping_id=attempt_mapping_id,
        attempts=attempts,
        error=final_error,
        build_log_tail=last_logs,
    )

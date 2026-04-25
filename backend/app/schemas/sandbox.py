from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from app.models import LabSourceKind, SandboxStatus
from app.schemas.vulnerability import CamelModel


class SandboxStartRequest(CamelModel):
    cve_id: str = Field(min_length=1, max_length=32)
    # Optional override — when caller knows better than the classifier.
    lab_kind: str | None = Field(default=None, max_length=128)
    # User-consent flag (PR9-E). When True the resolver may invoke the AI
    # synthesizer if no curated/generic lab covers this CVE. Defaults False
    # so a stray click never burns LLM tokens or build minutes.
    attempt_synthesis: bool = False


class InjectionPointOut(CamelModel):
    name: str
    method: str
    path: str
    parameter: str
    location: str
    response_kind: str
    notes: str = ""


class LabInfoOut(CamelModel):
    kind: str
    description: str
    target_path: str
    injection_points: list[InjectionPointOut] = []
    # One-line summary of how this lab was put together (base image,
    # injection shape, ...). Empty unless the synthesizer wrote one.
    digest: str = ""
    # Per-mapping vote tally (synthesized labs only). Always present so the
    # UI can render a stable layout — for vulhub/generic labs this is just
    # ``{0,0}`` and the buttons stay hidden.
    feedback_up: int = 0
    feedback_down: int = 0
    # Caller's previous vote on this mapping (so the UI can show the
    # toggled state). None when never voted or when no client header.
    my_vote: str | None = None
    # True when bad feedback caused the resolver to refuse this mapping
    # on the regular path. Surfaced so the UI can explain *why* the user
    # is being asked to consent to re-synthesis.
    degraded: bool = False


class SandboxSessionOut(CamelModel):
    id: UUID
    vulnerability_id: UUID | None = None
    lab_kind: str
    lab_source: LabSourceKind = LabSourceKind.GENERIC
    verified: bool = False
    container_name: str | None = None
    target_url: str | None = None
    status: SandboxStatus
    error: str | None = None
    last_run: dict | None = None
    created_at: datetime
    expires_at: datetime | None = None
    lab: LabInfoOut | None = None


class AdaptedPayloadOut(CamelModel):
    method: str
    path: str
    parameter: str
    location: str
    payload: str
    success_indicator: str
    rationale: str
    notes: str = ""
    # True when the payload was replayed from the known-good cache instead
    # of going through the LLM. The UI uses this to show "캐시 사용" badge.
    from_cache: bool = False


class RunVerdictOut(CamelModel):
    success: bool
    confidence: str
    summary: str
    evidence: str = ""
    next_step: str = ""
    heuristic_signal: str = ""


class ExchangeOut(CamelModel):
    url: str
    method: str
    status_code: int
    response_headers: dict[str, str]
    body: str
    body_truncated: bool


class SandboxExecRequest(CamelModel):
    # When omitted, the server pulls the latest AI analysis (if cached) or
    # asks the LLM for one and uses its payload_example as input.
    generic_payload: str | None = None
    # When True, ignore any cached known-good payload and force a fresh LLM
    # adaptation. Useful when the user wants to retry with a different
    # technique or when the lab spec changed.
    force_regenerate: bool = False


class SandboxExecResponse(CamelModel):
    session: SandboxSessionOut
    adapted: AdaptedPayloadOut
    exchange: ExchangeOut
    verdict: RunVerdictOut


class VulhubSyncResponse(CamelModel):
    folders_scanned: int
    candidates: int
    upserted: int
    skipped: int
    errors: list[str] = []


class SynthesizeRequest(CamelModel):
    cve_id: str = Field(min_length=1, max_length=32)
    # When True, ignore any existing verified ``synthesized`` mapping and
    # ask the LLM for a fresh build. Use sparingly — burns LLM tokens and
    # docker build minutes.
    force_regenerate: bool = False


class SynthesizeResponse(CamelModel):
    cve_id: str
    image_tag: str
    verified: bool
    mapping_id: int | None = None
    attempts: int
    error: str | None = None
    spec: dict | None = None
    payload: dict | None = None
    build_log_tail: list[str] = []
    response_status: int | None = None
    response_body_preview: str | None = None


class SynthesizeGcRequest(CamelModel):
    # All optional — omit to use the configured defaults from settings.
    target_total_mb: int | None = Field(default=None, ge=0)
    target_max_count: int | None = Field(default=None, ge=0)
    target_max_age_days: int | None = Field(default=None, ge=0)


class EvictedImageOut(CamelModel):
    cve_id: str
    image_tag: str
    size_mb: int
    reason: str


class SynthesizeGcResponse(CamelModel):
    scanned: int
    evicted: list[EvictedImageOut] = []
    freed_mb: int
    retained_count: int
    retained_total_mb: int
    skipped_in_use: list[str] = []


class SynthesizeCacheEntryOut(CamelModel):
    cve_id: str
    image_tag: str
    lab_kind: str
    size_mb: int
    in_use: bool
    image_present: bool
    last_used_at: datetime | None
    last_verified_at: datetime | None
    created_at: datetime
    age_days: int


class LabFeedbackRequest(CamelModel):
    # 'up' = the lab worked as expected; 'down' = lab is broken /
    # misleading. Anything else → 422.
    vote: str = Field(min_length=2, max_length=8)
    note: str | None = Field(default=None, max_length=500)


class LabFeedbackResponse(CamelModel):
    mapping_id: int
    feedback_up: int
    feedback_down: int
    my_vote: str | None
    degraded: bool


class SynthesizeCacheReport(CamelModel):
    count: int
    total_mb: int
    in_use_count: int
    missing_image_count: int
    oldest_last_used_at: datetime | None = None
    # Echo the configured ceilings so the UI can render utilization without
    # a separate /settings call.
    max_total_mb: int
    max_count: int
    max_age_days: int
    entries: list[SynthesizeCacheEntryOut] = []

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

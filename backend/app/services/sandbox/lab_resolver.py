"""Decide which lab to spawn for a given CVE — single entry point for the
whole resolver chain (vulhub → generic class → AI synthesis → reject).

The chain reads top-down:

  1. ``cve_lab_mappings`` row of kind ``vulhub`` for this exact CVE
     → highest fidelity, often a real reproducer of the bug.
  2. ``cve_lab_mappings`` row of kind ``synthesized`` (built by PR9-D)
     → AI-generated repro, only used when no vulhub mapping exists.
  3. In-code generic class lab matched by ``classify_vulnerability``
     → covers wide swaths of CVEs at low fidelity (current XSS lab).
  4. ``None`` → caller surfaces "not yet supported".

Kept separate from ``manager`` (which only knows how to *run* a ``LabSpec``)
so the resolver's policy stays testable in isolation and so future kinds
(e.g. AI synthesis) can be added by extending the chain instead of rewiring
the manager.

Also exposes ``record_success_payload`` — when an exec proves the AI-adapted
payload actually works, we cache the result on the mapping row so the next
call for the same (CVE, lab) skips the LLM entirely.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models import CveLabMapping, LabSourceKind, Vulnerability
from app.services.sandbox.catalog import LAB_CATALOG, InjectionPoint, LabDefinition
from app.services.sandbox.classifier import classify_vulnerability

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Typed lab spec — what the manager needs to know to spawn one container or
# stack. Kept agnostic of *where* the spec came from (vulhub vs generic vs
# synthesized).
# ---------------------------------------------------------------------------


@dataclass
class LabSpec:
    """Everything ``manager.start_lab`` needs to spin a lab up."""

    # How to spawn. ``image`` = single docker image; ``compose`` = multi-
    # container stack (PR9-B will teach the manager to handle this).
    run_kind: Literal["image", "compose"]
    lab_kind: str  # e.g. "xss" or "spring/CVE-2022-22965"
    description: str
    container_port: int  # port on the *target* container the backend will hit
    target_path: str  # path to GET to confirm liveness
    injection_points: list[InjectionPoint] = field(default_factory=list)

    # image-mode fields
    image: str | None = None

    # compose-mode fields
    compose_path: str | None = None  # filesystem path inside the backend image
    target_service: str | None = None  # which service in compose is the target

    build_hint: str = ""

    # Optional human-readable one-liner. Set by the synthesizer (PR9-I) and
    # surfaced in the CVE detail sidebar so the user can tell at a glance
    # what shape of lab the AI built. Empty for vulhub / generic specs.
    digest: str = ""

    # Per-mapping feedback tally (PR9-J). Only populated for specs derived
    # from a mapping row — generic-class labs without a row stay at zero.
    feedback_up: int = 0
    feedback_down: int = 0

    def expected_image(self) -> str:
        """Best-effort image identifier for error messages."""
        return self.image or f"compose:{self.compose_path}#{self.target_service}"


# ---------------------------------------------------------------------------
# Resolved lab: the spec + provenance + verified flag + optional cached
# payload (so exec can skip the AI adaptation call).
# ---------------------------------------------------------------------------


@dataclass
class ResolvedLab:
    spec: LabSpec
    source: LabSourceKind  # vulhub | generic | synthesized
    verified: bool
    mapping_id: int | None = None  # None if no DB row exists yet
    cached_payload: dict | None = None  # AdaptedPayload-shaped dict, or None


# ---------------------------------------------------------------------------
# Helpers — build LabSpec from each kind of source.
# ---------------------------------------------------------------------------


def _spec_from_generic(lab: LabDefinition) -> LabSpec:
    return LabSpec(
        run_kind="image",
        lab_kind=lab.kind,
        description=lab.description,
        image=lab.image,
        container_port=lab.container_port,
        target_path=lab.target_path,
        injection_points=list(lab.injection_points),
        build_hint=lab.build_hint,
    )


def _spec_from_mapping(mapping: CveLabMapping) -> LabSpec:
    """Reconstruct a LabSpec from the JSONB ``spec`` blob on a mapping row.

    For ``generic`` rows (which exist only to cache a payload) the mapping's
    ``spec`` is empty — caller should use ``_spec_from_generic`` against the
    in-code catalog instead.
    """
    s = mapping.spec or {}
    run_kind = s.get("run_kind", "image")
    raw_points = s.get("injection_points") or []
    points = [
        InjectionPoint(
            name=str(p.get("name", "")),
            method=str(p.get("method", "GET")),
            path=str(p.get("path", "/")),
            parameter=str(p.get("parameter", "")),
            location=str(p.get("location", "query")),
            response_kind=str(p.get("response_kind", "")),
            notes=str(p.get("notes", "")),
        )
        for p in raw_points
    ]
    return LabSpec(
        run_kind=run_kind,
        lab_kind=mapping.lab_kind,
        description=str(s.get("description", "")),
        image=s.get("image"),
        compose_path=s.get("compose_path"),
        target_service=s.get("target_service"),
        container_port=int(s.get("container_port", 80)),
        target_path=str(s.get("target_path", "/")),
        injection_points=points,
        build_hint=str(s.get("build_hint", "")),
        # Prefer the spec's digest field but fall back to the mapping's
        # ``notes`` column — older synthesized rows (pre-PR9-I) only stored
        # the digest there.
        digest=str(s.get("digest") or mapping.notes or ""),
        feedback_up=int(mapping.feedback_up or 0),
        feedback_down=int(mapping.feedback_down or 0),
    )


async def _find_mapping(
    db: AsyncSession, cve_id: str, kind: LabSourceKind
) -> CveLabMapping | None:
    return await db.scalar(
        select(CveLabMapping).where(
            CveLabMapping.cve_id == cve_id,
            CveLabMapping.kind == kind,
        )
    )


# ---------------------------------------------------------------------------
# Trust gating
# ---------------------------------------------------------------------------


def is_degraded(mapping: CveLabMapping) -> bool:
    """Return True when user feedback says this synthesized lab is broken
    enough that we should refuse to spawn it on the regular path.

    Heuristic kept deliberately simple: ≥2 down votes and downs strictly
    exceed ups by ≥2. That requires at least two distinct users to flag a
    lab and protects against a single grumpy session. The rule is read-
    only here; the synthesizer's 24h cooldown still gates re-synthesis
    even when ``attempt_synthesis=True`` arrives via the consent flow.
    """
    down = int(mapping.feedback_down or 0)
    up = int(mapping.feedback_up or 0)
    return down >= 2 and down >= up + 2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def resolve_lab(
    db: AsyncSession,
    vuln: Vulnerability,
    *,
    forced_kind: str | None = None,
    attempt_synthesis: bool = False,
) -> ResolvedLab | None:
    """Walk the resolver chain and return the best ResolvedLab for *vuln*.

    ``forced_kind`` lets the caller bypass the classifier and force a
    specific generic-class lab (e.g. user picked one from a dropdown).

    ``attempt_synthesis`` is the user-consent flag (PR9-E). When True and
    every prior chain step misses, the resolver triggers the AI synthesizer
    inline. The synthesizer enforces a 24h cooldown per CVE so consecutive
    consented calls don't burn tokens on persistent failures. When False
    (the default), the resolver behaves exactly as before.
    """
    cve_id = vuln.cve_id

    # 1. Curated CVE-specific mappings (vulhub > synthesized). Unverified
    #    synthesized rows are rate-limit placeholders, not runnable labs —
    #    skip them so the resolver doesn't return an empty spec.
    for kind in (LabSourceKind.VULHUB, LabSourceKind.SYNTHESIZED):
        mapping = await _find_mapping(db, cve_id, kind)
        if mapping is None:
            continue
        if kind == LabSourceKind.SYNTHESIZED and not mapping.verified:
            continue
        # Trust gating (PR9-J): a synthesized lab with bad feedback is
        # treated as if it didn't exist on the regular path. The chain
        # continues so the caller naturally falls into the no_lab consent
        # flow and can opt into re-synthesis.
        if kind == LabSourceKind.SYNTHESIZED and is_degraded(mapping):
            log.info(
                "sandbox.resolve.degraded_skip",
                cve_id=cve_id,
                lab_kind=mapping.lab_kind,
                feedback_up=mapping.feedback_up,
                feedback_down=mapping.feedback_down,
            )
            continue
        spec = _spec_from_mapping(mapping)
        log.info(
            "sandbox.resolve.mapping_hit",
            cve_id=cve_id,
            source=kind.value,
            lab_kind=mapping.lab_kind,
            verified=mapping.verified,
        )
        return ResolvedLab(
            spec=spec,
            source=kind,
            verified=mapping.verified,
            mapping_id=mapping.id,
            cached_payload=mapping.known_good_payload,
        )

    # 2. Generic class lab (in-code catalog).
    generic_kind = forced_kind or classify_vulnerability(vuln)
    if generic_kind:
        lab = LAB_CATALOG.get(generic_kind.lower())
        if lab is not None:
            cached_mapping = await db.scalar(
                select(CveLabMapping).where(
                    CveLabMapping.cve_id == cve_id,
                    CveLabMapping.kind == LabSourceKind.GENERIC,
                    CveLabMapping.lab_kind == lab.kind,
                )
            )
            log.info(
                "sandbox.resolve.generic_hit",
                cve_id=cve_id,
                lab_kind=lab.kind,
                cache_hit=cached_mapping is not None
                and cached_mapping.known_good_payload is not None,
            )
            return ResolvedLab(
                spec=_spec_from_generic(lab),
                source=LabSourceKind.GENERIC,
                verified=bool(cached_mapping and cached_mapping.verified),
                mapping_id=cached_mapping.id if cached_mapping else None,
                cached_payload=cached_mapping.known_good_payload
                if cached_mapping
                else None,
            )

    # 3. AI synthesis fallback — only when caller explicitly consented.
    #    Imported lazily so the resolver module stays importable without the
    #    docker SDK (synthesizer pulls in the manager which pulls in docker).
    if attempt_synthesis:
        from app.services.sandbox.synthesizer import synthesize

        log.info("sandbox.resolve.synthesize_attempt", cve_id=cve_id)
        result = await synthesize(db, vuln)
        if result.verified and result.mapping_id is not None:
            mapping = await db.get(CveLabMapping, result.mapping_id)
            if mapping is not None:
                spec = _spec_from_mapping(mapping)
                log.info(
                    "sandbox.resolve.synthesize_hit",
                    cve_id=cve_id,
                    lab_kind=mapping.lab_kind,
                )
                return ResolvedLab(
                    spec=spec,
                    source=LabSourceKind.SYNTHESIZED,
                    verified=True,
                    mapping_id=mapping.id,
                    cached_payload=mapping.known_good_payload,
                )
        log.info(
            "sandbox.resolve.synthesize_failed",
            cve_id=cve_id,
            error=result.error,
        )

    # 4. No lab fits.
    log.info("sandbox.resolve.miss", cve_id=cve_id)
    return None


async def record_success_payload(
    db: AsyncSession,
    *,
    cve_id: str,
    resolved: ResolvedLab,
    adapted_payload_dict: dict,
) -> CveLabMapping:
    """Persist a working AdaptedPayload so subsequent execs of the same
    (CVE, lab) skip the LLM call entirely.

    For generic-class labs, this may insert a fresh ``generic``-kind row;
    for vulhub/synthesized rows we update the existing one in place.
    """
    now = datetime.now(timezone.utc)
    mapping: CveLabMapping | None = None

    if resolved.mapping_id is not None:
        mapping = await db.get(CveLabMapping, resolved.mapping_id)

    if mapping is None:
        # Generic lab without an existing cache row — create one.
        mapping = CveLabMapping(
            cve_id=cve_id,
            kind=resolved.source,
            lab_kind=resolved.spec.lab_kind,
            spec={},  # generic specs live in code; row only carries the cache
            known_good_payload=adapted_payload_dict,
            verified=True,
            last_verified_at=now,
        )
        db.add(mapping)
    else:
        mapping.known_good_payload = adapted_payload_dict
        mapping.verified = True
        mapping.last_verified_at = now

    await db.flush()
    log.info(
        "sandbox.resolve.payload_cached",
        cve_id=cve_id,
        source=resolved.source.value,
        lab_kind=resolved.spec.lab_kind,
        mapping_id=mapping.id,
    )
    return mapping

"""Sandbox service — spawns ephemeral vulnerability-lab containers and runs
AI-adapted exploit payloads against them in an isolated network.

Public entry points are exposed lazily so importing the package doesn't pull
in the docker SDK unless the sandbox feature is actually used.
"""

from app.services.sandbox.catalog import LAB_CATALOG, LabDefinition, get_lab
from app.services.sandbox.classifier import classify_vulnerability
from app.services.sandbox.lab_resolver import (
    LabSpec,
    ResolvedLab,
    is_degraded,
    record_success_payload,
    resolve_lab,
)
from app.services.sandbox.sweeper import reap_expired_sessions
from app.services.sandbox.synthesizer import SynthesisResult, synthesize
from app.services.sandbox.synthesizer_gc import (
    CacheEntry,
    CacheReport,
    EvictedImage,
    GcStats,
    gc_synthesized_images,
    report_synthesized_cache,
)
from app.services.sandbox.vulhub_harvester import HarvestStats, sync_all as sync_vulhub

__all__ = [
    "LAB_CATALOG",
    "CacheEntry",
    "CacheReport",
    "EvictedImage",
    "GcStats",
    "HarvestStats",
    "LabDefinition",
    "LabSpec",
    "ResolvedLab",
    "SynthesisResult",
    "classify_vulnerability",
    "gc_synthesized_images",
    "get_lab",
    "is_degraded",
    "reap_expired_sessions",
    "record_success_payload",
    "report_synthesized_cache",
    "resolve_lab",
    "synthesize",
    "sync_vulhub",
]

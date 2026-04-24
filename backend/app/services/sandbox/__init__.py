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
    record_success_payload,
    resolve_lab,
)
from app.services.sandbox.sweeper import reap_expired_sessions
from app.services.sandbox.vulhub_harvester import HarvestStats, sync_all as sync_vulhub

__all__ = [
    "LAB_CATALOG",
    "HarvestStats",
    "LabDefinition",
    "LabSpec",
    "ResolvedLab",
    "classify_vulnerability",
    "get_lab",
    "reap_expired_sessions",
    "record_success_payload",
    "resolve_lab",
    "sync_vulhub",
]

"""Sandbox service — spawns ephemeral vulnerability-lab containers and runs
AI-adapted exploit payloads against them in an isolated network.

Public entry points are exposed lazily so importing the package doesn't pull
in the docker SDK unless the sandbox feature is actually used.
"""

from app.services.sandbox.catalog import LAB_CATALOG, LabDefinition, get_lab
from app.services.sandbox.classifier import classify_vulnerability

__all__ = [
    "LAB_CATALOG",
    "LabDefinition",
    "classify_vulnerability",
    "get_lab",
]

"""Plugin base for CVE source parsers.

Each concrete parser implements `fetch()` to yield raw dicts and `normalize()`
to map them into the shared schema. The orchestrator owns DB writes so
parsers stay pure-functional and easy to test.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

from app.models import OsFamily, RefType, Severity, Source


@dataclass
class ParsedReference:
    url: str
    ref_type: RefType = RefType.ADVISORY


@dataclass
class ParsedProduct:
    vendor: str
    product: str
    os_family: OsFamily = OsFamily.OTHER
    version_range: str | None = None
    cpe_string: str | None = None


@dataclass
class ParsedVulnerability:
    cve_id: str
    title: str
    description: str
    source: Source
    source_url: str
    summary: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: Severity | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    types: list[str] = field(default_factory=list)  # RCE, XSS, SQLi ...
    affected_products: list[ParsedProduct] = field(default_factory=list)
    references: list[ParsedReference] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)


class BaseParser(ABC):
    """Subclass to register a new source. Declare ``source`` classvar."""

    source: ClassVar[Source]
    name: ClassVar[str]

    @abstractmethod
    async def fetch(self, since: datetime | None = None) -> AsyncIterator[ParsedVulnerability]:
        """Yield normalized vulnerabilities since the given timestamp."""
        if False:
            yield  # pragma: no cover — satisfy type checker

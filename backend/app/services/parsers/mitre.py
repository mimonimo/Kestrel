"""MITRE cvelistV5 bulk parser (PR 10-AF).

Why not the public REST API?
    https://cveawg.mitre.org/api/cve/{id} works for single-record reads
    but the listing endpoint requires a CNA-issued ``CVE-API-ORG`` header
    we'd have to register for, and even with auth iterating ~340k
    records over HTTP is slow + rate-limited. The CVE Program publishes
    the *same* data as a single git repository
    (https://github.com/CVEProject/cvelistV5) — one JSON file per CVE,
    updated continuously. Cloning + walking the tree is dramatically
    faster than the API and needs no credentials.

Modes
    full       Walk every ``cves/**/*.json`` after cloning/pulling.
               Used for the initial backfill.
    delta      Only files modified in the last N days. Uses
               ``git log --since`` to enumerate paths, which catches both
               newly published CVEs and updates to existing ones.

Layout
    ``cves/{year}/{thousand}xxx/CVE-{year}-{n}.json`` — e.g.
    ``cves/2021/44xxx/CVE-2021-44228.json``.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import OsFamily, RefType, Severity, Source
from app.services.parsers.base import (
    BaseParser,
    ParsedProduct,
    ParsedReference,
    ParsedVulnerability,
)

log = get_logger(__name__)


_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

_OS_HINTS: dict[re.Pattern[str], OsFamily] = {
    re.compile(r"\bwindows\b", re.I): OsFamily.WINDOWS,
    re.compile(r"\b(linux|debian|ubuntu|fedora|rhel|centos|alpine|kernel)\b", re.I): OsFamily.LINUX,
    re.compile(r"\b(macos|mac os|darwin|osx)\b", re.I): OsFamily.MACOS,
    re.compile(r"\bandroid\b", re.I): OsFamily.ANDROID,
    re.compile(r"\bios\b", re.I): OsFamily.IOS,
}


# ---------------------------------------------------------------------------
# Git sync
# ---------------------------------------------------------------------------

def _run(cmd: list[str], *, cwd: str | None = None, timeout: int = 1200) -> str:
    res = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"command failed ({res.returncode}): {' '.join(cmd)}\n"
            f"stdout: {res.stdout.strip()[:400]}\n"
            f"stderr: {res.stderr.strip()[:400]}"
        )
    return res.stdout


def sync_repo() -> Path:
    """Clone the cvelistV5 repo on first call, fast-forward subsequently."""
    settings = get_settings()
    repo_path = Path(settings.mitre_repo_path)
    remote = settings.mitre_repo_remote
    needs_clone = not (repo_path / ".git").exists()
    if needs_clone:
        if repo_path.exists() and any(repo_path.iterdir()):
            raise RuntimeError(
                f"{repo_path} 가 존재하지만 git 저장소가 아니고 비어있지도 않습니다. "
                "수동으로 비우거나 mitre_repo_path 를 다른 경로로 변경하세요."
            )
        log.info("mitre.clone.start", path=str(repo_path), remote=remote)
        repo_path.mkdir(parents=True, exist_ok=True)
        _run(["git", "init", "-q", str(repo_path)])
        _run(["git", "remote", "add", "origin", remote], cwd=str(repo_path))
        # cvelistV5 is huge (~5GB). Shallow clone keeps it ~2GB and avoids
        # pulling years of history we don't need.
        _run(
            ["git", "fetch", "--depth", "1", "origin", "HEAD"],
            cwd=str(repo_path),
            timeout=3600,
        )
        _run(["git", "reset", "--hard", "FETCH_HEAD"], cwd=str(repo_path))
        log.info("mitre.clone.done", path=str(repo_path))
        return repo_path

    log.info("mitre.pull.start", path=str(repo_path))
    _run(
        ["git", "fetch", "--depth", "1", "origin", "HEAD"],
        cwd=str(repo_path),
        timeout=1800,
    )
    _run(["git", "reset", "--hard", "FETCH_HEAD"], cwd=str(repo_path))
    head = _run(["git", "rev-parse", "FETCH_HEAD"], cwd=str(repo_path)).strip()
    log.info("mitre.pull.done", path=str(repo_path), head=head[:12])
    return repo_path


# ---------------------------------------------------------------------------
# JSON → ParsedVulnerability
# ---------------------------------------------------------------------------

def _first_desc(descriptions: list[dict[str, Any]] | None) -> str:
    if not descriptions:
        return ""
    # Prefer English; fall back to whichever lang is first.
    for d in descriptions:
        if (d.get("lang") or "").lower().startswith("en"):
            return (d.get("value") or "").strip()
    return (descriptions[0].get("value") or "").strip()


def _coerce_severity(raw: str | None, score: float | None) -> Severity | None:
    if raw:
        s = _SEVERITY_MAP.get(raw.upper())
        if s:
            return s
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _extract_metric(metrics: list[dict[str, Any]] | None) -> tuple[float | None, str | None, str | None]:
    """Return (score, vector, severity) using the highest-version CVSS available.

    cvss v4 > v3.1 > v3.0 > v2 — pick the first present in that order.
    """
    if not metrics:
        return None, None, None
    keys = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV3", "cvssV2_0", "cvssV2")
    for m in metrics:
        for key in keys:
            v = m.get(key)
            if not isinstance(v, dict):
                continue
            score = v.get("baseScore")
            vector = v.get("vectorString")
            severity = v.get("baseSeverity")
            try:
                score_f = float(score) if score is not None else None
            except (TypeError, ValueError):
                score_f = None
            return score_f, vector, severity
    return None, None, None


def _extract_cwes(problem_types: list[dict[str, Any]] | None) -> list[str]:
    if not problem_types:
        return []
    out: list[str] = []
    for pt in problem_types:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId") or ""
            if cwe.startswith("CWE-"):
                out.append(cwe)
    # De-dup preserving order.
    seen: set[str] = set()
    uniq: list[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _detect_os(text: str) -> OsFamily:
    for pat, fam in _OS_HINTS.items():
        if pat.search(text):
            return fam
    return OsFamily.OTHER


def _extract_products(affected: list[dict[str, Any]] | None, fallback_text: str) -> list[ParsedProduct]:
    out: list[ParsedProduct] = []
    if not affected:
        return out
    for a in affected:
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        if not vendor and not product:
            continue
        # Aggregate version ranges into a human string. cvelistV5
        # versions[] entries look like {version: "1.0", status: "affected",
        # versionType: "semver", lessThan: "1.5"}.
        ranges: list[str] = []
        for v in (a.get("versions") or []):
            if (v.get("status") or "").lower() != "affected":
                continue
            ver = (v.get("version") or "").strip()
            lt = (v.get("lessThan") or "").strip()
            lte = (v.get("lessThanOrEqual") or "").strip()
            if ver and lt:
                ranges.append(f"{ver} ≤ x < {lt}")
            elif ver and lte:
                ranges.append(f"{ver} ≤ x ≤ {lte}")
            elif ver:
                ranges.append(ver)
        version_range = ", ".join(ranges)[:128] or None

        # CPE strings (where present) are the canonical identifier; pick
        # the first if available.
        cpe_string = None
        for cpe in a.get("cpes") or []:
            if isinstance(cpe, str) and cpe.startswith("cpe:"):
                cpe_string = cpe[:256]
                break

        text_for_os = " ".join(filter(None, [vendor, product, fallback_text]))
        os_fam = _detect_os(text_for_os)
        out.append(
            ParsedProduct(
                vendor=vendor[:128] or "unknown",
                product=product[:128] or "unknown",
                os_family=os_fam,
                version_range=version_range,
                cpe_string=cpe_string,
            )
        )
    return out


def _extract_refs(refs: list[dict[str, Any]] | None) -> list[ParsedReference]:
    if not refs:
        return []
    out: list[ParsedReference] = []
    for r in refs:
        url = (r.get("url") or "").strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        tags = [t.lower() for t in (r.get("tags") or [])]
        if any("exploit" in t for t in tags):
            ref_type = RefType.EXPLOIT
        elif any("patch" in t for t in tags):
            ref_type = RefType.PATCH
        elif any(("write-up" in t) or ("writeup" in t) for t in tags):
            ref_type = RefType.WRITEUP
        else:
            ref_type = RefType.ADVISORY
        out.append(ParsedReference(url=url[:1024], ref_type=ref_type))
    return out


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # cvelistV5 timestamps look like "2021-12-10T10:15:00Z" or
        # "2021-12-10T10:15:00.000Z" or with ±HH:MM offset.
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _record_to_parsed(record: dict[str, Any]) -> ParsedVulnerability | None:
    meta = record.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id:
        return None
    state = (meta.get("state") or "").upper()
    if state != "PUBLISHED":
        # REJECTED / RESERVED records have empty containers — skip.
        return None
    cna = (record.get("containers") or {}).get("cna") or {}
    description = _first_desc(cna.get("descriptions"))
    if not description:
        # Without a description there's nothing useful to display.
        return None
    title = (cna.get("title") or "").strip() or description.split("\n", 1)[0][:200]

    score, vector, severity_raw = _extract_metric(cna.get("metrics"))
    severity = _coerce_severity(severity_raw, score)
    cwes = _extract_cwes(cna.get("problemTypes"))
    products = _extract_products(cna.get("affected"), description)
    references = _extract_refs(cna.get("references"))

    published_at = _parse_iso(meta.get("datePublished"))
    modified_at = _parse_iso(meta.get("dateUpdated") or meta.get("dateReserved"))

    source_url = f"https://www.cve.org/CVERecord?id={cve_id}"

    return ParsedVulnerability(
        cve_id=cve_id,
        title=title[:512],
        description=description,
        source=Source.MITRE,
        source_url=source_url,
        cvss_score=score,
        cvss_vector=vector,
        severity=severity,
        published_at=published_at,
        modified_at=modified_at,
        types=cwes,
        affected_products=products,
        references=references,
        raw_data=record,
    )


# ---------------------------------------------------------------------------
# File walkers
# ---------------------------------------------------------------------------

def _walk_all_files(root: Path) -> list[Path]:
    """Walk ``cves/{year}/{thousand}xxx/*.json`` deterministically."""
    cves_dir = root / "cves"
    if not cves_dir.exists():
        raise RuntimeError(
            f"{cves_dir} not found — repo layout unexpected. Did the cvelistV5 "
            "structure change?"
        )
    out: list[Path] = []
    for year_dir in sorted(cves_dir.iterdir()):
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue
        for bucket in sorted(year_dir.iterdir()):
            if not bucket.is_dir():
                continue
            for f in sorted(bucket.iterdir()):
                if f.is_file() and f.name.endswith(".json"):
                    out.append(f)
    return out


def _walk_recent_files(root: Path, since: datetime) -> list[Path]:
    """Files modified in git since the given timestamp."""
    since_iso = since.astimezone(timezone.utc).isoformat()
    out_lines = _run(
        ["git", "log", "--name-only", "--pretty=format:", f"--since={since_iso}", "--", "cves"],
        cwd=str(root),
        timeout=300,
    ).splitlines()
    seen: set[str] = set()
    out: list[Path] = []
    for line in out_lines:
        line = line.strip()
        if not line or not line.endswith(".json"):
            continue
        if line in seen:
            continue
        seen.add(line)
        f = root / line
        if f.exists():
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

class MitreParser(BaseParser):
    source: ClassVar[Source] = Source.MITRE
    name: ClassVar[str] = "MITRE"

    def __init__(self, *, mode: str = "delta", since_days: int = 7, max_records: int | None = None) -> None:
        # ``mode='full'`` walks every JSON file; ``delta`` only files
        # modified in git in the last ``since_days``.
        self.mode = mode
        self.since_days = since_days
        self.max_records = max_records

    async def fetch(self, since: datetime | None = None) -> AsyncIterator[ParsedVulnerability]:
        # git operations are blocking — push to thread.
        await asyncio.to_thread(sync_repo)
        repo_path = Path(get_settings().mitre_repo_path)
        if self.mode == "full":
            files = await asyncio.to_thread(_walk_all_files, repo_path)
        else:
            cutoff = since or (datetime.now(timezone.utc) - timedelta(days=self.since_days))
            files = await asyncio.to_thread(_walk_recent_files, repo_path, cutoff)
        log.info("mitre.walk.done", mode=self.mode, files=len(files))

        emitted = 0
        for f in files:
            if self.max_records and emitted >= self.max_records:
                break
            try:
                data = await asyncio.to_thread(_read_json, f)
            except Exception as e:
                log.warning("mitre.read_failed", file=str(f), error=str(e))
                continue
            parsed = _record_to_parsed(data)
            if parsed is None:
                continue
            emitted += 1
            yield parsed
            # Yield to event loop occasionally so HTTP healthchecks etc
            # aren't starved during a multi-hour backfill.
            if emitted % 200 == 0:
                await asyncio.sleep(0)


def _read_json(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

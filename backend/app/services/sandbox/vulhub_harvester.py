"""Pull the vulhub repo and turn each CVE folder into a ``cve_lab_mappings`` row.

This is **AI-free** by design — vulhub is curated, deterministic data and
should never burn LLM tokens to ingest. Each vulhub CVE folder ships with:

  * ``docker-compose.yml`` — multi-container reproducer.
  * ``README.md`` / ``README.zh-cn.md`` — human-readable description.

We walk the cloned repo, pick folders that look like CVE reproducers (one or
more ``CVE-YYYY-NNNN`` segments anywhere in the path or a ``cve.txt`` file),
parse the compose file just enough to figure out which service is the target
and which port it exposes, and upsert a row into ``cve_lab_mappings`` of
``kind=vulhub``.

The ``spec`` JSONB blob is shaped so ``lab_resolver._spec_from_mapping`` can
turn it back into a ``LabSpec(run_kind="compose", ...)`` without further IO.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import CveLabMapping, LabSourceKind

log = get_logger(__name__)

# Recognises any "CVE-YYYY-NNNN[N...]" token. vulhub uses both UPPER and lower
# (e.g. "CVE-2017-12615" and "cve-2017-12615"); be liberal.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Matches "host:container" or "host:container/proto" or just "container"
_PORT_RE = re.compile(r"^(?:(?P<host>\d+):)?(?P<container>\d+)(?:/\w+)?$")


@dataclass
class HarvestStats:
    folders_scanned: int = 0
    candidates: int = 0  # had at least one CVE token
    upserted: int = 0  # rows inserted or updated
    skipped: int = 0  # candidate but unparseable
    errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


# ---------------------------------------------------------------------------
# Git sync — clone on first run, fast-forward on subsequent runs.
# ---------------------------------------------------------------------------


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 600) -> str:
    """Run a subprocess and return stdout. Raises on non-zero exit."""
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
            f"stdout: {res.stdout.strip()}\n"
            f"stderr: {res.stderr.strip()}"
        )
    return res.stdout


def sync_repo() -> Path:
    """Clone vulhub on first call, fast-forward on subsequent calls.

    Returns the absolute path of the local checkout *as the backend container
    sees it* (use :func:`host_path_for` to translate to a host path for
    docker-compose invocations).
    """
    settings = get_settings()
    repo_path = Path(settings.vulhub_repo_path)
    remote = settings.vulhub_repo_remote

    needs_clone = (
        not repo_path.exists()
        or not (repo_path / ".git").exists()
    )
    if needs_clone:
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        # If the directory exists but is non-empty *and* not a git repo,
        # bail out — we'd otherwise risk wiping operator data.
        if repo_path.exists() and any(repo_path.iterdir()):
            raise RuntimeError(
                f"{repo_path} 가 존재하지만 git 저장소가 아니고 비어있지도 않습니다. "
                "수동으로 비우거나 VULHUB_REPO_PATH 를 다른 경로로 변경하세요."
            )
        # ``git clone`` won't clone into an existing dir even if empty.
        # Use ``git init + git remote add + git fetch + git reset`` instead
        # so the bind-mounted directory itself becomes the work tree.
        log.info("vulhub.clone.start", path=str(repo_path), remote=remote)
        repo_path.mkdir(parents=True, exist_ok=True)
        _run(["git", "init", "-q", str(repo_path)])
        _run(["git", "remote", "add", "origin", remote], cwd=str(repo_path))
        _run(
            ["git", "fetch", "--depth", "1", "origin", "HEAD"],
            cwd=str(repo_path),
            timeout=900,
        )
        _run(["git", "reset", "--hard", "FETCH_HEAD"], cwd=str(repo_path))
        log.info("vulhub.clone.done", path=str(repo_path))
        return repo_path

    log.info("vulhub.pull.start", path=str(repo_path))
    _run(["git", "fetch", "--depth", "1", "origin"], cwd=str(repo_path))
    # Hard reset to origin's tip — vulhub upstream is the source of truth.
    head = _run(["git", "rev-parse", "origin/HEAD"], cwd=str(repo_path)).strip()
    _run(["git", "reset", "--hard", head], cwd=str(repo_path))
    log.info("vulhub.pull.done", path=str(repo_path), head=head[:12])
    return repo_path


def host_path_for(container_path: Path | str) -> str:
    """Translate a container-side path to its host-side equivalent.

    Returns the path string the *host* docker daemon will see when we pass
    it to ``docker compose -f``.
    """
    settings = get_settings()
    container_root = Path(settings.vulhub_repo_path).resolve()
    host_root = Path(settings.vulhub_host_path)
    rel = Path(container_path).resolve().relative_to(container_root)
    return str(host_root / rel)


# ---------------------------------------------------------------------------
# Compose / README parsers — best-effort, never raise on malformed inputs.
# ---------------------------------------------------------------------------


def _read_compose(compose_path: Path) -> dict | None:
    try:
        with compose_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as e:
        log.debug("vulhub.compose.unreadable", path=str(compose_path), error=str(e))
        return None
    if not isinstance(data, dict):
        return None
    return data


def _pick_target_service(compose: dict) -> tuple[str, int] | None:
    """Pick the service we should treat as the lab target + its container port.

    Heuristic: prefer the first service whose ``ports:`` entry maps to a
    container port we can recognise. Falls back to the first service overall
    if none have ports.
    """
    services = compose.get("services") or {}
    if not isinstance(services, dict) or not services:
        return None

    # Pass 1 — any service with a parseable ports entry.
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        ports = svc.get("ports") or []
        if not isinstance(ports, list):
            continue
        for entry in ports:
            container_port = _extract_container_port(entry)
            if container_port is not None:
                return str(name), container_port

    # Pass 2 — fall back to first service + ``expose`` or default 80.
    first_name, first_svc = next(iter(services.items()))
    if isinstance(first_svc, dict):
        expose = first_svc.get("expose") or []
        if isinstance(expose, list) and expose:
            try:
                return str(first_name), int(str(expose[0]).split("/")[0])
            except ValueError:
                pass
    return str(first_name), 80


def _extract_container_port(entry) -> int | None:
    if isinstance(entry, int):
        return entry
    if isinstance(entry, str):
        m = _PORT_RE.match(entry.strip())
        if m:
            return int(m.group("container"))
        return None
    if isinstance(entry, dict):
        # long-form: {target: 80, published: 8080, protocol: tcp}
        target = entry.get("target")
        if isinstance(target, int):
            return target
        if isinstance(target, str) and target.isdigit():
            return int(target)
    return None


def _read_readme_description(folder: Path) -> str:
    """Extract a one-paragraph description from the folder's README, if any."""
    for name in ("README.md", "README.en.md", "README.zh-cn.md", "README.txt"):
        p = folder / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        return _first_paragraph(text)
    return ""


def _first_paragraph(text: str) -> str:
    """Return the first prose paragraph after the H1 title, trimmed.

    vulhub READMEs follow a stable shape:
        # CVE-YYYY-NNNN
        <one-line summary>

        ## Description / 漏洞描述
        <long form>

    We grab the first non-empty paragraph after the H1 line, falling back to
    the first paragraph in the file if the H1 is missing.
    """
    lines = text.splitlines()
    paragraphs: list[str] = []
    buf: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            if buf:
                paragraphs.append(" ".join(buf).strip())
                buf = []
            continue
        if not stripped:
            if buf:
                paragraphs.append(" ".join(buf).strip())
                buf = []
            continue
        buf.append(stripped)
    if buf:
        paragraphs.append(" ".join(buf).strip())

    for p in paragraphs:
        if len(p) > 20:  # skip badge lines / one-word entries
            return p[:600]
    return paragraphs[0][:600] if paragraphs else ""


def _cve_ids_for_folder(folder: Path, repo_root: Path) -> list[str]:
    """Return all CVE identifiers attributable to *folder*.

    Sources, in order: the relative path under repo_root (vulhub uses
    CVE-named directories), and any ``cve.txt`` file in the folder.
    """
    rel = folder.relative_to(repo_root).as_posix()
    found: list[str] = [m.upper() for m in _CVE_RE.findall(rel)]

    cve_txt = folder / "cve.txt"
    if cve_txt.exists():
        try:
            text = cve_txt.read_text(encoding="utf-8", errors="replace")
            found.extend(m.upper() for m in _CVE_RE.findall(text))
        except OSError:
            pass

    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


# ---------------------------------------------------------------------------
# Top-level harvest — walk the repo and upsert mappings.
# ---------------------------------------------------------------------------


async def sync_all(db: AsyncSession) -> HarvestStats:
    """Sync the vulhub checkout and (re)build all vulhub mappings.

    Heavy lifting (git + filesystem walk + YAML parse) runs in a thread so
    the FastAPI event loop stays responsive. DB writes happen on the calling
    coroutine via *db*.
    """
    repo_path = await asyncio.to_thread(sync_repo)
    folders, stats = await asyncio.to_thread(_walk_repo, repo_path)

    for folder, compose, target_service, container_port, description in folders:
        rel = folder.relative_to(repo_path).as_posix()
        cves = _cve_ids_for_folder(folder, repo_path)
        if not cves:
            stats.skipped += 1
            continue

        spec = {
            "run_kind": "compose",
            "compose_path": host_path_for(folder / "docker-compose.yml"),
            "target_service": target_service,
            "container_port": container_port,
            "target_path": "/",
            "description": description or f"vulhub: {rel}",
            "injection_points": [],  # vulhub doesn't pre-declare these
            "build_hint": (
                f"docker compose -f {host_path_for(folder / 'docker-compose.yml')} build"
            ),
        }

        for cve_id in cves:
            await _upsert(db, cve_id=cve_id, lab_kind=rel, spec=spec)
            stats.upserted += 1

    await db.commit()
    log.info(
        "vulhub.sync.done",
        scanned=stats.folders_scanned,
        candidates=stats.candidates,
        upserted=stats.upserted,
        skipped=stats.skipped,
    )
    return stats


def _walk_repo(repo_root: Path) -> tuple[list[tuple], HarvestStats]:
    stats = HarvestStats()
    out: list[tuple] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # Skip vulhub's internal infra dirs and git plumbing.
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", ".github", "base", "docs", "scripts"}
        ]
        if "docker-compose.yml" not in filenames and "docker-compose.yaml" not in filenames:
            continue
        stats.folders_scanned += 1
        folder = Path(dirpath)

        cves = _cve_ids_for_folder(folder, repo_root)
        if not cves:
            continue
        stats.candidates += 1

        compose_name = (
            "docker-compose.yml" if "docker-compose.yml" in filenames
            else "docker-compose.yaml"
        )
        compose = _read_compose(folder / compose_name)
        if compose is None:
            stats.skipped += 1
            stats.errors.append(f"{folder.relative_to(repo_root)}: compose unreadable")
            continue

        picked = _pick_target_service(compose)
        if picked is None:
            stats.skipped += 1
            stats.errors.append(f"{folder.relative_to(repo_root)}: no service")
            continue
        target_service, container_port = picked

        description = _read_readme_description(folder)
        out.append((folder, compose, target_service, container_port, description))
    return out, stats


async def _upsert(
    db: AsyncSession,
    *,
    cve_id: str,
    lab_kind: str,
    spec: dict,
) -> None:
    """Insert or refresh a vulhub mapping row for *cve_id*.

    We only write if the lab_kind or spec actually changed — avoids touching
    ``updated_at`` on every nightly sync when nothing meaningful moved.
    """
    existing = await db.scalar(
        select(CveLabMapping).where(
            CveLabMapping.cve_id == cve_id,
            CveLabMapping.kind == LabSourceKind.VULHUB,
        )
    )
    now = datetime.now(timezone.utc)
    if existing is None:
        db.add(
            CveLabMapping(
                cve_id=cve_id,
                kind=LabSourceKind.VULHUB,
                lab_kind=lab_kind,
                spec=spec,
                verified=False,
                last_verified_at=None,
                notes=f"harvested from vulhub at {now.isoformat()}",
            )
        )
        return
    if existing.lab_kind != lab_kind or existing.spec != spec:
        existing.lab_kind = lab_kind
        existing.spec = spec
        existing.notes = f"harvested from vulhub at {now.isoformat()}"


# ---------------------------------------------------------------------------
# Operator helpers — used by tests and the API endpoint.
# ---------------------------------------------------------------------------


def reset_local_repo() -> None:
    """Wipe the local checkout — forces the next sync to fresh-clone.

    Only intended for operator/test use; the API does not expose this.
    """
    settings = get_settings()
    p = Path(settings.vulhub_repo_path)
    if p.exists():
        shutil.rmtree(p)
        log.info("vulhub.reset", path=str(p))

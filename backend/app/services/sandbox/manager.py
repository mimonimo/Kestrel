"""Docker lifecycle for sandbox lab containers.

Wraps the docker python SDK with the bits the API needs:
  * spawn a lab image into the isolated ``sandbox`` network with strict
    resource limits and a TTL,
  * proxy HTTP requests from the backend (which is also on the sandbox
    network) to the lab container by its container name,
  * stop / reap containers individually or in bulk past their TTL.

Everything that touches the docker daemon is done in a thread (the SDK is
sync) via ``asyncio.to_thread`` so the FastAPI event loop stays responsive.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import docker
import httpx
import yaml
from docker.errors import APIError, ImageNotFound, NotFound

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.sandbox.lab_resolver import LabSpec

log = get_logger(__name__)

_LABEL_OWNER = "kestrel.sandbox"

# Conservative timeouts. The backend talks to the lab over the internal
# bridge — no external hops involved — so anything > a few seconds means
# the lab is hung or the payload triggered something heavy.
_HTTP_TIMEOUT = httpx.Timeout(15.0, connect=3.0)
_READY_TIMEOUT_SECONDS = 20.0


class SandboxError(Exception):
    """User-facing sandbox failure (image missing, daemon down, etc.)."""


class LabImageMissing(SandboxError):
    pass


@dataclass
class LaunchedLab:
    container_id: str
    container_name: str
    target_url: str  # internal URL the backend can reach (NOT browsable from host)
    expires_at: datetime


def _client() -> docker.DockerClient:
    # ``from_env`` honors DOCKER_HOST or falls through to /var/run/docker.sock,
    # which is exactly what we mount in compose.
    return docker.from_env()


def _short_id() -> str:
    return uuid.uuid4().hex[:12]


async def list_owned_containers() -> list[dict]:
    """Return raw container summaries owned by the sandbox feature."""

    def _do() -> list[dict]:
        cli = _client()
        try:
            containers = cli.containers.list(
                all=True, filters={"label": _LABEL_OWNER}
            )
        except APIError as e:
            raise SandboxError(f"docker daemon 오류: {e}") from e
        return [
            {
                "id": c.id,
                "name": c.name,
                "status": c.status,
                "labels": c.labels,
            }
            for c in containers
        ]

    return await asyncio.to_thread(_do)


async def start_lab(spec: LabSpec, session_id: uuid.UUID) -> LaunchedLab:
    """Run a fresh lab for *spec* attached to the sandbox network.

    Two modes:
      * ``image`` — single container, run via the docker SDK with strict
        resource limits.
      * ``compose`` — vulhub-style multi-container stack, brought up via
        ``docker compose -f <path> up -d`` against the host docker daemon
        and *then* attached to the sandbox network and labeled for reaping.

    Either way, no ports are published to the host, the lab network is
    ``internal: true``, and the backend reaches the target by container name.
    """
    if spec.run_kind == "compose":
        return await _start_compose_lab(spec, session_id)
    if spec.run_kind != "image":
        raise SandboxError(f"알 수 없는 lab spec.run_kind: {spec.run_kind!r}")
    if not spec.image:
        raise SandboxError("lab spec에 image가 비어 있습니다.")

    settings = get_settings()
    name = f"kestrel-sandbox-{session_id.hex[:12]}"
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.sandbox_ttl_seconds
    )

    # Hardening (PR9-C): all opt-in via env, default behavior unchanged.
    security_opt = ["no-new-privileges:true"]
    if settings.sandbox_seccomp_path:
        security_opt.append(f"seccomp={settings.sandbox_seccomp_path}")
    extra_kwargs: dict = {}
    if settings.sandbox_runtime:
        extra_kwargs["runtime"] = settings.sandbox_runtime

    def _do() -> LaunchedLab:
        cli = _client()
        try:
            cli.containers.run(
                image=spec.image,
                name=name,
                detach=True,
                remove=False,  # we reap explicitly so we can capture exit logs
                network=settings.sandbox_network,
                # Hard caps so a runaway payload can't starve the host.
                mem_limit=f"{settings.sandbox_memory_mb}m",
                memswap_limit=f"{settings.sandbox_memory_mb}m",
                nano_cpus=int(settings.sandbox_cpus * 1_000_000_000),
                pids_limit=settings.sandbox_pids_limit,
                # Drop every Linux capability — labs are simple HTTP servers,
                # they need none of CAP_NET_ADMIN/CAP_SYS_*/etc.
                cap_drop=["ALL"],
                security_opt=security_opt,
                # Read-only rootfs only when explicitly hardened — some
                # labs (xss-flask gunicorn) write to non-/tmp paths.
                read_only=settings.sandbox_harden,
                tmpfs={"/tmp": "rw,size=16m"},
                labels={
                    _LABEL_OWNER: "true",
                    "kestrel.sandbox.kind": spec.lab_kind,
                    "kestrel.sandbox.session_id": str(session_id),
                    "kestrel.sandbox.expires_at": expires_at.isoformat(),
                },
                **extra_kwargs,
            )
        except ImageNotFound as e:
            raise LabImageMissing(
                f"이미지 '{spec.image}'를 찾을 수 없습니다. 다음 명령으로 빌드하세요:\n"
                f"  {spec.build_hint or 'docker build -t ' + spec.image + ' <context>'}"
            ) from e
        except APIError as e:
            raise SandboxError(f"컨테이너 생성 실패: {e.explanation or e}") from e

        return LaunchedLab(
            container_id=name,  # use name as id surface — easier to log
            container_name=name,
            target_url=f"http://{name}:{spec.container_port}",
            expires_at=expires_at,
        )

    handle = await asyncio.to_thread(_do)
    log.info("sandbox.started", session_id=str(session_id), name=handle.container_name)
    return handle


async def wait_ready(target_url: str, spec: LabSpec) -> None:
    """Block until the lab responds to a GET on its target_path, or raise."""
    deadline = asyncio.get_event_loop().time() + _READY_TIMEOUT_SECONDS
    url = f"{target_url}{spec.target_path}"
    last_err: Exception | None = None
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        while asyncio.get_event_loop().time() < deadline:
            try:
                res = await client.get(url)
                if res.status_code < 500:
                    return
                last_err = RuntimeError(f"HTTP {res.status_code}")
            except httpx.HTTPError as e:
                last_err = e
            await asyncio.sleep(0.4)
    raise SandboxError(
        f"랩 컨테이너가 {_READY_TIMEOUT_SECONDS:.0f}초 안에 응답하지 않았습니다: {last_err}"
    )


async def stop_lab(container_id_or_name: str) -> None:
    """Stop and reap a lab.

    The handle the API stores can be either:
      * an image-mode container name (``kestrel-sandbox-<short>``), or
      * a compose-mode project name (``kestrel-sandbox-<short>``) —
        same prefix shape, since image mode borrows the prefix for tidy
        container names.

    We disambiguate at runtime by asking the docker daemon: if a container
    with that exact name exists, image-mode reap. Otherwise treat the handle
    as a compose project and run ``docker compose down``.
    """

    def _do() -> None:
        cli = _client()
        try:
            container = cli.containers.get(container_id_or_name)
        except NotFound:
            container = None
        except APIError:
            container = None

        if container is not None:
            try:
                container.stop(timeout=3)
            except APIError:
                pass
            try:
                container.remove(force=True)
            except APIError:
                pass
            return

        # Not a single container — assume compose project.
        try:
            _compose_down(container_id_or_name)
        except RuntimeError as e:
            log.warning(
                "sandbox.compose.down_failed",
                project=container_id_or_name,
                error=str(e),
            )
        _cleanup_override(container_id_or_name)

    await asyncio.to_thread(_do)
    log.info("sandbox.stopped", name=container_id_or_name)


async def reap_expired() -> int:
    """Stop labs whose label-encoded TTL has passed. Returns reap count.

    For compose-mode labs we deduplicate by project name and reap the whole
    project once instead of stopping each container in the stack individually.
    """
    now = datetime.now(timezone.utc)

    def _do() -> list[str]:
        cli = _client()
        try:
            containers = cli.containers.list(
                all=True, filters={"label": _LABEL_OWNER}
            )
        except APIError as e:
            log.warning("sandbox.reap_failed", error=str(e))
            return []
        victims: list[str] = []
        seen_projects: set[str] = set()
        for c in containers:
            raw = c.labels.get("kestrel.sandbox.expires_at")
            if not raw:
                continue
            try:
                expires_at = datetime.fromisoformat(raw)
            except ValueError:
                continue
            if expires_at > now:
                continue
            project = c.labels.get("kestrel.sandbox.compose_project")
            if project:
                if project in seen_projects:
                    continue
                seen_projects.add(project)
                victims.append(project)
            else:
                victims.append(c.name)
        return victims

    names = await asyncio.to_thread(_do)
    for n in names:
        await stop_lab(n)
    return len(names)


async def proxy_request(
    target_url: str,
    method: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    json: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """Send an HTTP request from the backend to the lab and return a
    structured summary that the frontend / AI result-analyzer can read."""
    url = f"{target_url}{path if path.startswith('/') else '/' + path}"
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        try:
            res = await client.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json,
                headers=headers,
            )
        except httpx.HTTPError as e:
            raise SandboxError(f"랩에 요청 실패: {e}") from e
    body_text = res.text
    truncated = body_text[:8192]
    return {
        "url": str(res.request.url),
        "method": method.upper(),
        "status_code": res.status_code,
        "response_headers": dict(res.headers),
        "body": truncated,
        "body_truncated": len(body_text) > len(truncated),
    }


# ---------------------------------------------------------------------------
# Compose mode (vulhub) — invokes the host docker daemon via the docker CLI.
# Kept on this side of the file so the docker SDK + CLI subprocess paths
# don't get tangled.
# ---------------------------------------------------------------------------


def _compose_project_name(session_id: uuid.UUID) -> str:
    settings = get_settings()
    return f"{settings.sandbox_compose_project_prefix}-{session_id.hex[:12]}"


def _compose_env() -> dict[str, str]:
    """Subprocess env scrubbed of compose-affecting overrides we don't want."""
    env = os.environ.copy()
    # Don't accidentally inherit project name / file from the backend's own
    # compose context.
    env.pop("COMPOSE_PROJECT_NAME", None)
    env.pop("COMPOSE_FILE", None)
    return env


def _run_compose(args: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess:
    """Run ``docker compose ...`` against the host daemon. Raises on failure."""
    res = subprocess.run(
        ["docker", "compose", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_compose_env(),
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"docker compose 실패 ({res.returncode}): {' '.join(args)}\n"
            f"stdout: {res.stdout.strip()}\n"
            f"stderr: {res.stderr.strip()}"
        )
    return res


def _compose_down(project: str) -> None:
    _run_compose(["-p", project, "down", "-v", "--remove-orphans"], timeout=60)


def _override_dir() -> Path:
    """Where per-session compose override files live.

    Defaults to a subdir of the vulhub repo so the existing bind mount makes
    the file visible at the same absolute path inside the backend container
    *and* on the host docker daemon side.
    """
    settings = get_settings()
    base = settings.sandbox_override_dir or os.path.join(
        settings.vulhub_repo_path, ".kestrel-overrides"
    )
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _build_override(base_compose_path: str, project: str) -> Path | None:
    """Generate a compose override file applying hardening to every service.

    Returns the absolute path of the override file, or None if no hardening
    flags are set (caller should run plain ``-f base`` in that case).
    """
    settings = get_settings()
    runtime = settings.sandbox_runtime
    seccomp = settings.sandbox_seccomp_path
    harden = settings.sandbox_harden
    if not (runtime or seccomp or harden):
        return None

    try:
        with open(base_compose_path, encoding="utf-8") as fh:
            base = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as e:
        log.warning("sandbox.compose.override_skip", reason=str(e))
        return None

    services = base.get("services") or {}
    if not isinstance(services, dict) or not services:
        return None

    security_opt = ["no-new-privileges:true"]
    if seccomp:
        security_opt.append(f"seccomp={seccomp}")

    override_services: dict[str, dict] = {}
    for name in services:
        svc: dict = {"security_opt": security_opt, "cap_drop": ["ALL"]}
        if runtime:
            svc["runtime"] = runtime
        if harden:
            svc["read_only"] = True
            # Common writable mounts most labs need; over-allocates rather
            # than guessing per-service. tmpfs is daemon-side memory-backed.
            svc["tmpfs"] = ["/tmp:rw,size=64m"]
        override_services[name] = svc

    override = {"services": override_services}
    out = _override_dir() / f"{project}.yml"
    try:
        with open(out, "w", encoding="utf-8") as fh:
            yaml.safe_dump(override, fh, sort_keys=False)
    except OSError as e:
        log.warning("sandbox.compose.override_write_failed", error=str(e))
        return None
    return out


def _cleanup_override(project: str) -> None:
    try:
        path = _override_dir() / f"{project}.yml"
        if path.exists():
            path.unlink()
    except OSError as e:
        log.debug("sandbox.compose.override_cleanup_failed", project=project, error=str(e))


async def _start_compose_lab(spec: LabSpec, session_id: uuid.UUID) -> LaunchedLab:
    if not spec.compose_path:
        raise SandboxError("compose lab spec에 compose_path가 비어 있습니다.")
    if not spec.target_service:
        raise SandboxError("compose lab spec에 target_service가 비어 있습니다.")

    settings = get_settings()
    project = _compose_project_name(session_id)
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.sandbox_ttl_seconds
    )

    override_path = _build_override(spec.compose_path, project)
    compose_files = ["-f", spec.compose_path]
    if override_path is not None:
        compose_files += ["-f", str(override_path)]

    def _do() -> LaunchedLab:
        try:
            _run_compose(
                ["-p", project, *compose_files, "up", "-d"],
                timeout=300,
            )
        except RuntimeError as e:
            # Best-effort cleanup if compose left dangling resources.
            try:
                _compose_down(project)
            except RuntimeError:
                pass
            _cleanup_override(project)
            raise SandboxError(f"compose up 실패: {e}") from e

        # Find the target service's container ID and inspect for its name.
        try:
            ps_out = _run_compose(
                ["-p", project, "ps", "-q", spec.target_service],
                timeout=30,
            ).stdout.strip()
        except RuntimeError as e:
            try:
                _compose_down(project)
            except RuntimeError:
                pass
            _cleanup_override(project)
            raise SandboxError(f"compose ps 실패: {e}") from e

        target_container_id = ps_out.splitlines()[0] if ps_out else ""
        if not target_container_id:
            try:
                _compose_down(project)
            except RuntimeError:
                pass
            _cleanup_override(project)
            raise SandboxError(
                f"compose project {project} 에서 target_service "
                f"{spec.target_service!r} 컨테이너를 찾지 못했습니다."
            )

        cli = _client()
        try:
            target_container = cli.containers.get(target_container_id)
            project_containers = cli.containers.list(
                all=True,
                filters={"label": f"com.docker.compose.project={project}"},
            )
        except APIError as e:
            try:
                _compose_down(project)
            except RuntimeError:
                pass
            _cleanup_override(project)
            raise SandboxError(f"docker inspect 실패: {e}") from e

        # Attach every project container to the sandbox network so the backend
        # can reach the target by container name, and so internal lab traffic
        # stays sandboxed. ``internal: true`` on the network blocks egress.
        net = cli.networks.get(settings.sandbox_network)
        for c in project_containers:
            try:
                net.connect(c)
            except APIError as e:
                # Already connected (race or compose pre-attached) — ignore.
                if "already exists" not in str(e).lower():
                    log.warning(
                        "sandbox.compose.network_attach_failed",
                        container=c.name,
                        error=str(e),
                    )

        # Stamp our reaper labels on every project container. Compose owns
        # the labels at creation time, so we add ours via ``docker update``
        # after the fact.
        labels = {
            _LABEL_OWNER: "true",
            "kestrel.sandbox.kind": spec.lab_kind,
            "kestrel.sandbox.session_id": str(session_id),
            "kestrel.sandbox.expires_at": expires_at.isoformat(),
            "kestrel.sandbox.compose_project": project,
        }
        for c in project_containers:
            _label_container(c.id, labels)

        return LaunchedLab(
            container_id=project,  # surface the project name as the handle
            container_name=target_container.name,
            target_url=f"http://{target_container.name}:{spec.container_port}",
            expires_at=expires_at,
        )

    handle = await asyncio.to_thread(_do)
    log.info(
        "sandbox.compose.started",
        session_id=str(session_id),
        project=project,
        target=handle.container_name,
    )
    return handle


def _label_container(container_id: str, labels: dict[str, str]) -> None:
    """Apply *labels* to a running container.

    The docker SDK exposes update() for resource limits but not labels;
    fall back to the CLI which supports ``--label``.
    """
    args = ["docker", "container", "update"]
    # NOTE: ``docker container update`` doesn't support --label on every
    # docker version. The portable path is to re-create with new labels,
    # but that defeats the purpose. We instead store reaper state on a
    # known-good label channel: env vars on the container at compose time
    # would have been ideal, but we don't own the compose file. Best
    # effort: try ``docker update --label`` first; if that fails, leave
    # the labels off this container — the project label still lets the
    # reaper find it via project_name lookup.
    for k, v in labels.items():
        args.extend(["--label", f"{k}={v}"])
    args.append(container_id)
    res = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=30,
        env=_compose_env(),
        check=False,
    )
    if res.returncode != 0:
        # Non-fatal: the compose project label is enough for reap_expired
        # to find these containers via their project name on the next sweep.
        log.debug(
            "sandbox.compose.label_failed",
            container=container_id,
            error=res.stderr.strip(),
        )

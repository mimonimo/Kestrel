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
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import docker
import httpx
from docker.errors import APIError, ImageNotFound, NotFound

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.sandbox.catalog import LabDefinition

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


async def start_lab(lab: LabDefinition, session_id: uuid.UUID) -> LaunchedLab:
    """Run a fresh container of *lab* attached to the sandbox network.

    The container has no host port published, no internet egress (the
    network is ``internal: true``), and tight CPU/memory/PID limits. The
    backend reaches it by container name across the sandbox bridge.
    """
    settings = get_settings()
    name = f"kestrel-sandbox-{session_id.hex[:12]}"
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.sandbox_ttl_seconds
    )

    def _do() -> LaunchedLab:
        cli = _client()
        try:
            cli.containers.run(
                image=lab.image,
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
                security_opt=["no-new-privileges:true"],
                read_only=False,  # some labs (xss-flask gunicorn) want /tmp
                tmpfs={"/tmp": "rw,size=16m"},
                labels={
                    _LABEL_OWNER: "true",
                    "kestrel.sandbox.kind": lab.kind,
                    "kestrel.sandbox.session_id": str(session_id),
                    "kestrel.sandbox.expires_at": expires_at.isoformat(),
                },
            )
        except ImageNotFound as e:
            raise LabImageMissing(
                f"이미지 '{lab.image}'를 찾을 수 없습니다. 다음 명령으로 빌드하세요:\n"
                f"  {lab.build_hint or 'docker build -t ' + lab.image + ' <context>'}"
            ) from e
        except APIError as e:
            raise SandboxError(f"컨테이너 생성 실패: {e.explanation or e}") from e

        return LaunchedLab(
            container_id=name,  # use name as id surface — easier to log
            container_name=name,
            target_url=f"http://{name}:{lab.container_port}",
            expires_at=expires_at,
        )

    handle = await asyncio.to_thread(_do)
    log.info("sandbox.started", session_id=str(session_id), name=handle.container_name)
    return handle


async def wait_ready(target_url: str, lab: LabDefinition) -> None:
    """Block until the lab responds to a GET on its target_path, or raise."""
    deadline = asyncio.get_event_loop().time() + _READY_TIMEOUT_SECONDS
    url = f"{target_url}{lab.target_path}"
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
    def _do() -> None:
        cli = _client()
        try:
            container = cli.containers.get(container_id_or_name)
        except NotFound:
            return
        try:
            container.stop(timeout=3)
        except APIError:
            pass
        try:
            container.remove(force=True)
        except APIError:
            pass

    await asyncio.to_thread(_do)
    log.info("sandbox.stopped", name=container_id_or_name)


async def reap_expired() -> int:
    """Stop containers whose label-encoded TTL has passed. Returns count."""
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
        for c in containers:
            raw = c.labels.get("kestrel.sandbox.expires_at")
            if not raw:
                continue
            try:
                expires_at = datetime.fromisoformat(raw)
            except ValueError:
                continue
            if expires_at <= now:
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

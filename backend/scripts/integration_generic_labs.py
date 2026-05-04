"""Live integration smoke — spin each generic lab on the sandbox network,
fire its matching backend probe, expect passed=True.

This catches what the unit smokes can't: image-actually-runs,
docker-DNS-resolves, probe-payload-actually-triggers, canary-side-channel-
works. Run inside the backend container so docker.from_env() hits the
mounted host socket and the network DNS works the same as in real
sessions.

Each scenario:
  1. ``docker run`` the lab image on settings.sandbox_network as
     ``kestrel-itest-<kind>-<rand>`` so we can find it later.
  2. Wait for /healthz (or `/`) to respond.
  3. Build a LaunchedLab pointing at ``http://<container_name>:5000``.
  4. Pull the lab's first injection_point from LAB_CATALOG.
  5. ``probe.run(handle=lab, ip=ip)`` — we expect passed=True.
  6. Cleanup: kill + remove the lab container.

Exit code 0 if every kind passes; 1 with a per-kind report otherwise.
"""
from __future__ import annotations

import asyncio
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import docker
import httpx
from docker.errors import APIError, NotFound

from app.core.config import get_settings
from app.services.sandbox.catalog import LAB_CATALOG
from app.services.sandbox.synthesizer_probes import select_probes


@dataclass
class LiveHandle:
    container_id: str
    container_name: str
    target_url: str
    expires_at: datetime


# Kind → (lab image is published, internal port, expected-pass probe name).
# Skip kinds whose probes need slow runs (sqli randomblob takes 4-8s) but
# include them for coverage.
KINDS = ["xss", "rce", "sqli", "ssti", "path-traversal", "ssrf", "auth-bypass",
         "xxe", "open-redirect", "deserialization"]
EXPECTED_PROBE = {
    "xss": "xss_reflect_nonce",
    "rce": "rce_canary_read",
    "sqli": "sqli_time_blind",
    "ssti": "ssti_arithmetic",
    "path-traversal": "path_traversal_canary",
    "ssrf": "ssrf_inbound_canary",
    "auth-bypass": "auth_bypass_differential",
    "xxe": "xxe_canary_read",
    "open-redirect": "open_redirect_nonce",
    "deserialization": "deser_pickle_canary_write",
}


async def _wait_healthy(url: str, timeout_s: float = 30.0) -> bool:
    """Poll <url>/healthz until 200 or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout_s
    async with httpx.AsyncClient(timeout=2.0) as client:
        while asyncio.get_event_loop().time() < deadline:
            try:
                r = await client.get(f"{url}/healthz")
                if r.status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
    return False


async def _spawn_lab(kind: str) -> LiveHandle:
    settings = get_settings()
    lab_def = LAB_CATALOG[kind]
    name = f"kestrel-itest-{kind.replace('-', '')}-{secrets.token_hex(3)}"
    cli = docker.from_env()
    cli.containers.run(
        image=lab_def.image,
        name=name,
        detach=True,
        remove=False,
        network=settings.sandbox_network,
        mem_limit="256m",
        memswap_limit="256m",
        nano_cpus=int(0.5 * 1_000_000_000),
        pids_limit=128,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        tmpfs={"/tmp": "rw,size=16m"},
        labels={"kestrel.sandbox.kind": f"itest-{kind}"},
    )
    target_url = f"http://{name}:{lab_def.container_port}"
    if not await _wait_healthy(target_url):
        # Surface the lab logs so we know why it didn't bind
        try:
            c = cli.containers.get(name)
            logs = c.logs(tail=40).decode(errors="replace")
        except APIError:
            logs = "(could not fetch logs)"
        await _kill(name)
        raise RuntimeError(f"{kind}: 랩이 30s 안에 healthz 200 안 줌. logs:\n{logs}")
    return LiveHandle(
        container_id=name,
        container_name=name,
        target_url=target_url,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


async def _kill(name: str) -> None:
    cli = docker.from_env()
    try:
        c = cli.containers.get(name)
    except NotFound:
        return
    try:
        c.kill()
    except APIError:
        pass
    try:
        c.remove(force=True)
    except APIError:
        pass


async def _run_one(kind: str) -> tuple[bool, str]:
    """Returns (passed, message)."""
    lab_def = LAB_CATALOG[kind]
    if not lab_def.injection_points:
        return False, "no injection_points"
    ip = lab_def.injection_points[0]
    probes = select_probes(ip.response_kind)
    expected = EXPECTED_PROBE[kind]
    probe = next((p for p in probes if p.name == expected), None)
    if probe is None:
        names = [p.name for p in probes]
        return False, f"expected probe {expected} not in {names}"

    print(f"  [{kind}] spawning {lab_def.image}…", flush=True)
    try:
        handle = await _spawn_lab(kind)
    except Exception as e:  # noqa: BLE001 — surface to report
        return False, f"spawn failed: {e}"

    try:
        print(f"  [{kind}] running probe {probe.name} against {ip.path}?{ip.parameter}=…", flush=True)
        outcome = await probe.run(handle=handle, ip=ip)  # type: ignore[arg-type]
        if outcome.passed:
            return True, f"PASS — {outcome.rationale[:140]}"
        return False, f"FAIL — passed=False rationale={outcome.rationale[:240]}"
    finally:
        await _kill(handle.container_name)


async def main() -> int:
    print(f"Live integration smoke against {len(KINDS)} generic labs.\n")
    results: list[tuple[str, bool, str]] = []
    for kind in KINDS:
        ok, msg = await _run_one(kind)
        results.append((kind, ok, msg))
        print(f"  → {kind}: {'PASS' if ok else 'FAIL'} — {msg}\n", flush=True)

    print("=" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"Summary: {passed}/{len(KINDS)} passed.")
    for kind, ok, msg in results:
        print(f"  {'✓' if ok else '✗'} {kind:>14}  {msg[:120]}")
    return 0 if passed == len(KINDS) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

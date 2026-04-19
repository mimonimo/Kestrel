"""Operator endpoints — manual ingestion triggers with per-request key overrides.

The frontend settings page POSTs saved NVD / GitHub keys here so the user can
validate them with a fresh pull. Keys are used for the duration of the request
only; they are never written to the DB or env.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Header

from app.core.logging import get_logger
from app.services.ingestion import run_parser
from app.services.parsers import ExploitDbParser, GithubAdvisoryParser, NvdParser

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/refresh")
async def refresh_ingestion(
    background: BackgroundTasks,
    x_nvd_api_key: str | None = Header(default=None, alias="X-NVD-API-Key"),
    x_github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
) -> dict:
    """Kick off one ingestion run per source, using the provided keys if any.

    Runs in the background so the HTTP call returns immediately — the caller
    should poll ``/status`` to see each source's latest log row update."""

    async def _run_all() -> None:
        await asyncio.gather(
            run_parser(NvdParser(api_key_override=x_nvd_api_key)),
            run_parser(GithubAdvisoryParser(token_override=x_github_token)),
            run_parser(ExploitDbParser()),
            return_exceptions=True,
        )

    background.add_task(_run_all)
    return {
        "queued": True,
        "usedKeys": {
            "nvd": bool(x_nvd_api_key),
            "github": bool(x_github_token),
        },
    }

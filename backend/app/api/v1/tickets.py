"""Tickets API — anonymous CVE triage state per client.

Each browser (X-Client-Id) can attach one ticket per CVE with a status
(open / in_progress / resolved / ignored) and an optional note. Used as
the user's personal "to-do board" for CVEs they've decided to act on.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Ticket, TicketStatus
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/tickets", tags=["tickets"])


def _require_client(x_client_id: str | None) -> str:
    if not x_client_id or len(x_client_id) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Client-Id header is required",
        )
    return x_client_id


class TicketUpsert(CamelModel):
    cve_id: str = Field(min_length=3, max_length=32)
    status: TicketStatus = TicketStatus.OPEN
    note: str | None = Field(default=None, max_length=4000)


class TicketPatch(CamelModel):
    status: TicketStatus | None = None
    note: str | None = Field(default=None, max_length=4000)


class TicketOut(CamelModel):
    id: int
    cve_id: str
    status: TicketStatus
    note: str | None
    created_at: datetime
    updated_at: datetime


class TicketListResponse(CamelModel):
    items: list[TicketOut]
    total: int
    counts: dict[str, int]


@router.get("", response_model=TicketListResponse, response_model_by_alias=True)
async def list_tickets(
    status_filter: TicketStatus | None = Query(default=None, alias="status"),
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> TicketListResponse:
    cid = _require_client(x_client_id)
    stmt = select(Ticket).where(Ticket.client_id == cid)
    if status_filter is not None:
        stmt = stmt.where(Ticket.status == status_filter)
    stmt = stmt.order_by(Ticket.updated_at.desc())
    rows = (await db.execute(stmt)).scalars().all()

    counts_stmt = (
        select(Ticket.status, func.count(Ticket.id))
        .where(Ticket.client_id == cid)
        .group_by(Ticket.status)
    )
    counts_rows = (await db.execute(counts_stmt)).all()
    counts = {s.value: 0 for s in TicketStatus}
    for s, n in counts_rows:
        counts[s.value] = n

    items = [
        TicketOut(
            id=t.id,
            cve_id=t.cve_id,
            status=t.status,
            note=t.note,
            created_at=t.created_at,
            updated_at=t.updated_at,
        )
        for t in rows
    ]
    return TicketListResponse(items=items, total=len(items), counts=counts)


@router.put("", response_model=TicketOut, response_model_by_alias=True)
async def upsert_ticket(
    body: TicketUpsert,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> TicketOut:
    cid = _require_client(x_client_id)
    existing = (
        await db.execute(
            select(Ticket).where(Ticket.client_id == cid, Ticket.cve_id == body.cve_id)
        )
    ).scalar_one_or_none()

    if existing:
        existing.status = body.status
        existing.note = body.note
        ticket = existing
    else:
        ticket = Ticket(
            client_id=cid, cve_id=body.cve_id, status=body.status, note=body.note
        )
        db.add(ticket)

    await db.commit()
    await db.refresh(ticket)
    return TicketOut(
        id=ticket.id,
        cve_id=ticket.cve_id,
        status=ticket.status,
        note=ticket.note,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
    )


@router.patch("/{cve_id}", response_model=TicketOut, response_model_by_alias=True)
async def patch_ticket(
    cve_id: str,
    body: TicketPatch,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> TicketOut:
    cid = _require_client(x_client_id)
    ticket = (
        await db.execute(
            select(Ticket).where(Ticket.client_id == cid, Ticket.cve_id == cve_id)
        )
    ).scalar_one_or_none()
    if not ticket:
        raise HTTPException(status_code=404, detail="ticket not found")
    if body.status is not None:
        ticket.status = body.status
    if body.note is not None:
        ticket.note = body.note
    await db.commit()
    await db.refresh(ticket)
    return TicketOut(
        id=ticket.id,
        cve_id=ticket.cve_id,
        status=ticket.status,
        note=ticket.note,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
    )


@router.delete("/{cve_id}", status_code=204)
async def delete_ticket(
    cve_id: str,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> None:
    cid = _require_client(x_client_id)
    await db.execute(
        delete(Ticket).where(Ticket.client_id == cid, Ticket.cve_id == cve_id)
    )
    await db.commit()

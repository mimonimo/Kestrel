from __future__ import annotations

from app.schemas.vulnerability import CamelModel, VulnerabilityListItem


class SearchResponse(CamelModel):
    items: list[VulnerabilityListItem]
    total: int
    page: int
    page_size: int

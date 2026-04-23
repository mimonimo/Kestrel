from fastapi import APIRouter

from app.api.v1 import (
    admin,
    assets,
    bookmarks,
    community,
    cves,
    health,
    sandbox,
    search,
    settings,
    tickets,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(cves.router)
api_router.include_router(search.router)
api_router.include_router(community.router)
api_router.include_router(admin.router)
api_router.include_router(assets.router)
api_router.include_router(bookmarks.router)
api_router.include_router(tickets.router)
api_router.include_router(settings.router)
api_router.include_router(sandbox.router)

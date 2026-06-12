from fastapi import APIRouter

from app.api.v1 import (
    admin,
    analysis,
    analysis_records,
    assets,
    auth,
    bookmarks,
    claude_auth,
    community,
    cves,
    dashboard,
    health,
    notifications,
    profile,
    resources,
    reports,
    search,
    settings,
    stats,
    tickets,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(stats.router)
api_router.include_router(auth.router)
api_router.include_router(profile.router)
api_router.include_router(cves.router)
api_router.include_router(search.router)
api_router.include_router(community.router)
api_router.include_router(admin.router)
api_router.include_router(assets.router)
api_router.include_router(notifications.router)
api_router.include_router(bookmarks.router)
api_router.include_router(reports.router)
api_router.include_router(tickets.router)
api_router.include_router(settings.router)
api_router.include_router(resources.router)
api_router.include_router(claude_auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(analysis.router)
# 분석 기록 (PR 10-CN): 내것 / 커뮤니티 / CVE 별 / 단건
api_router.include_router(analysis_records.me_router)
api_router.include_router(analysis_records.community_router)
api_router.include_router(analysis_records.cve_records_router)
api_router.include_router(analysis_records.analyses_router)

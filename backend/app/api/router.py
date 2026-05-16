"""Top-level API router."""
from fastapi import APIRouter

from app.api import admin, ai, analytics, auth, cves, kev, news, policy_ai, profiles, reports, telemetry

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(cves.router)
api_router.include_router(news.router)
api_router.include_router(profiles.router)
api_router.include_router(reports.router)
api_router.include_router(telemetry.router)
api_router.include_router(kev.router)
api_router.include_router(analytics.policies_router)
api_router.include_router(analytics.compliance_router)
api_router.include_router(analytics.asset_router)
api_router.include_router(analytics.geo_router)
api_router.include_router(ai.router)
api_router.include_router(policy_ai.router)
api_router.include_router(admin.router)

"""
Core API routes
"""
import sys

from fastapi import APIRouter, Request, Security
from fastapi import __version__ as fastapi_version
from fastapi.responses import RedirectResponse

from .. import __version__ as app_version
from .. import db, security, settings

router = APIRouter()

app_info = {
    "app_version": app_version,
    "framework_version": fastapi_version,
    "lang_version": sys.version,
    "environment": settings.api.env,
    "engine": str(db.engine),
}


@router.get(
    "/",
    include_in_schema=False,
    dependencies=[Security(security.authorize)],
)
async def index(request: Request) -> RedirectResponse:
    target_url = request.url_for("index_api")
    return RedirectResponse(url=target_url)


@router.get("/lb-status", include_in_schema=False)
async def health_check() -> dict[str, str]:
    """Provides a health check endpoint for the Load Balancer."""
    return app_info

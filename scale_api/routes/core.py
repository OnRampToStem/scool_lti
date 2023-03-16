"""
Core API routes
"""
import sys

from fastapi import APIRouter, Request, Security
from fastapi import __version__ as fastapi_version
from fastapi.responses import RedirectResponse

from .. import __version__ as app_version
from .. import db, security
from ..settings import app_config

router = APIRouter()


@router.get("/", dependencies=[Security(security.authorize)])
async def index(request: Request):
    target_url = request.url_for("index_api")
    return RedirectResponse(url=target_url)


@router.get("/lb-status")
async def health_check():
    """Provides a health check endpoint for the Load Balancer."""
    return {
        "app_version": app_version,
        "framework_version": fastapi_version,
        "lang_version": sys.version,
        "environment": app_config.api.env,
        "engine": str(db.engine),
    }

# Student Centered Open Online Learning (SCOOL) LTI Integration
# Copyright (c) 2021-2024  Fresno State University, SCOOL Project Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
API Endpoints

Contains the configuration for all API endpoint routers.
"""

import logging
import sys

from fastapi import APIRouter, Request, Security
from fastapi import __version__ as fastapi_version
from fastapi.responses import RedirectResponse

from .. import __version__ as app_version
from .. import db, security, settings
from . import auth, lti_v13, well_known

logger = logging.getLogger(__name__)

router = APIRouter()

app_info = {
    "app_version": app_version,
    "framework_version": fastapi_version,
    "lang_version": sys.version,
    "environment": settings.api.env,
    "engine": str(db.engine.sync_engine),
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


router.include_router(
    auth.router,
    prefix="/v1/auth",
    tags=["Authentication"],
)

router.include_router(
    well_known.router,
    prefix="/.well-known",
    tags=["Well Known"],
)

router.include_router(
    lti_v13.router,
    prefix="/lti/v1.3",
    tags=["LTI 1.3"],
)

logger.info("Routes configured: %s", app_info)

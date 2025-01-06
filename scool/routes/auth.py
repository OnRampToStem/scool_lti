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
Authentication routes

Provides endpoints for authentication for ``AuthUser`` requests
and token services for ``ScoolUser`` requests.
"""

import logging
import urllib.parse
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPBasic
from pydantic import BaseModel

from .. import (
    db,
    schemas,
    security,
    settings,
    templates,
)

logger = logging.getLogger(__name__)

router = APIRouter()

ScoolUser = Annotated[schemas.ScoolUser, Depends(security.req_scool_user)]

# We also support HTTP Basic auth as a fallback for Bearer tokens
HTTPBasicParser = HTTPBasic(auto_error=False)


class OAuth20Response(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa:S105
    expires_in: int


@router.get("/", include_in_schema=False)
async def index_api(request: Request, scool_user: ScoolUser) -> Response:
    scool_user.name = "Demo User"
    scool_user.context = {
        "id": "demo-scool-edu",
        "title": "SCOOL Demo Course",
    }
    target_url = urllib.parse.urljoin(
        str(request.url_for("index_api")),
        settings.FRONTEND_LAUNCH_PATH,
    )
    token = security.create_scool_user_token(scool_user, expires_in=60 * 60 * 12)
    return templates.redirect_lms_auth(target_url, token)


@router.get("/userinfo")
async def user_info(scool_user: ScoolUser) -> schemas.ScoolUser:
    return scool_user


@router.post("/oauth/token")
async def oauth_token(
    request: Request,
    grant_type: Annotated[str, Form()],
    scope: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> OAuth20Response:
    """OAuth 2.0 Token Endpoint.

    This endpoint supports the ``client_credentials`` grant type and is
    used in order to authenticate ``AuthUser`` clients for API calls.
    """
    if grant_type != "client_credentials":
        logger.error("oauth token unsupported grant_type [%s] requested", grant_type)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request"},
        )

    if not client_id or not client_secret:
        if basic_auth := await HTTPBasicParser(request):
            client_id = basic_auth.username
            client_secret = basic_auth.password
        else:
            logger.error("oauth token request missing credentials")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_client"},
            )

    logger.info("oauth_token(scopes=%r)", scope)

    try:
        auth_user = await db.store.user_by_client_id(client_id=client_id)
    except LookupError:
        logger.warning("oauth token client not found: %s", client_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client"},
        ) from None

    if not security.verify_password(client_secret, auth_user.client_secret_hash):
        logger.error("oauth token invalid password AuthUser: %s", auth_user)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client"},
        )

    token = security.create_auth_user_token(auth_user)
    logger.info("Return token for AuthUser: %s", auth_user)
    return OAuth20Response(
        access_token=token,
        expires_in=settings.OAUTH_ACCESS_TOKEN_EXPIRY,
    )

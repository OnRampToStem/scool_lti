"""
Authentication routes

Provides endpoints for authentication for ``AuthUser`` requests
and token services for ``ScaleUser`` requests.
"""
import logging
import urllib.parse

from fastapi import (
    APIRouter,
    Depends,
    Form,
    Request,
    Response,
    Security,
    status,
)
from fastapi.security import HTTPBasic

from .. import (
    db,
    schemas,
    security,
    templates,
)
from ..settings import app_config

logger = logging.getLogger(__name__)

router = APIRouter()

# Use this just for extracting the basic auth for the client_credentials auth
http_basic = HTTPBasic(auto_error=False)


@router.get(
    "/",
    include_in_schema=False,
    dependencies=[Security(security.authorize)],
)
async def index_api(
    request: Request,
    scale_user: schemas.ScaleUser = Depends(security.req_scale_user),
):
    scale_user.name = "Demo User"
    scale_user.context = {
        "id": "demo-or2stem-edu",
        "title": "SCALE Demo Course",
    }
    target_url = urllib.parse.urljoin(
        str(request.url_for("index_api")),
        app_config.api.frontend_launch_path,
    )
    token = security.create_scale_user_token(scale_user, expires_in=60 * 60 * 12)
    return templates.redirect_lms_auth(target_url, token)


@router.get(
    "/userinfo",
    dependencies=[Depends(security.authorize)],
    response_model=schemas.AuthUser,
    response_model_exclude={"client_secret_hash"},
)
def user_info(request: Request):
    """User Info endpoint."""
    return request.state.auth_user


@router.post("/oauth/token")
async def oauth_token(
    request: Request,
    response: Response,
    grant_type: str = Form(...),
    scope: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
):
    """OAuth 2.0 Token Endpoint.

    This endpoint supports the ``client_credentials`` grant type and is
    used in order to authenticate ``AuthUser`` clients for API calls.
    """
    if grant_type != "client_credentials":
        logger.error("oauth token unsupported grant_type [%s] requested", grant_type)
        response.status_code = 400
        return {"error": "invalid_request"}

    if not client_id or not client_secret:
        basic_auth = await http_basic(request)
        if basic_auth:
            client_id = basic_auth.username
            client_secret = basic_auth.password
        else:
            logger.error("oauth token request missing credentials")
            response.status_code = 400
            return {"error": "invalid_client"}

    # TODO: verify scope?
    logger.info("oauth_token(scopes=%r)", scope)

    try:
        auth_user = await db.store.user_by_client_id_async(client_id)
    except LookupError:
        logger.warning("oauth token client not found: %s", client_id)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "invalid_client"}

    if not security.verify_password(client_secret, auth_user.client_secret_hash):
        logger.error("oauth token invalid password AuthUser: %s", auth_user)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "invalid_client"}

    token = security.create_auth_user_token(auth_user)
    logger.info("Return token for AuthUser: %s", auth_user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": app_config.api.oauth_access_token_expiry,
    }

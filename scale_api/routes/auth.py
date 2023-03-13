"""
Authentication routes

Provides endpoints for authentication for ``AuthUser`` requests
and token services for ``ScaleUser`` requests.
"""
import base64
import logging
import urllib.parse
import uuid
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
    Security,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic

from scale_api import (
    app_config,
    auth,
    db,
    schemas,
    templates,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Use this just for extracting the basic auth for the client_credentials auth
http_basic = HTTPBasic(auto_error=False)


@router.get("/", include_in_schema=False)
async def index_api(request: Request):
    context = build_context(request)
    return templates.render(request, "index.html", context)


@router.get("/logout", include_in_schema=False)
async def logout(request: Request):
    request.session.clear()
    target_url = request.url_for("index_api")
    logger.info("logout redirecting to: %s", target_url)
    return RedirectResponse(url=target_url, status_code=302)


@router.post("/login", include_in_schema=False)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    verify_request(request, csrf_token)
    try:
        auth_user = await db.store.user_by_client_id_async(username)
    except LookupError:
        logger.info("login found no user for: %s", username)
        request.state.login_error = "Incorrect username or password"
        return await index_api(request)

    if not auth.verify_password(password, auth_user.client_secret_hash):
        logger.error("login invalid password for: %s", username)
        request.state.login_error = "Incorrect username or password"
        return await index_api(request)

    request.session["au"] = auth_user.session_dict()
    logger.info("Login AuthUser: %s", auth_user)

    scale_user = schemas.ScaleUser.from_auth_user(auth_user)
    scale_user.name = "Demo User"
    scale_user.context = {
        "id": "demo-or2stem-edu",
        "title": "SCALE Demo Course",
    }
    target_url = urllib.parse.urljoin(
        str(request.url_for("index_api")),
        app_config.FRONTEND_V2_LAUNCH_PATH,
    )
    context = {
        "token": auth.create_scale_user_token(
            scale_user,
            expires_in=60 * 60 * 12,
        ),
        "target_url": target_url,
    }
    return templates.render(request, "scale_lms_auth.html", context)


@router.get(
    "/token",
    include_in_schema=False,
    dependencies=[Security(auth.authorize)],
)
async def session_user_token(request: Request):
    """The ``ScaleUser`` token endpoint.

    This endpoint provides authentication tokens to the front-end
    webapp. The ``ScaleUser`` is stored in the web session so this
    requires that the request be generated from the same origin or
    if from cross-origin that ``withCredentials`` be specified in
    the xhr call.
    """
    state = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    scale_user = request.state.scale_user
    logger.info("[%s]: token request found ScaleUser: %s", state, scale_user)
    expiry = 60 * 60 * 8  # provide an 8-hour token for Scale users
    user_token = auth.create_scale_user_token(scale_user, expires_in=expiry)
    return {"token": user_token}


@router.post("/token")
async def scale_user_token_impersonate(
    request: Request,
    response: Response,
    scale_user_request: schemas.ScaleUserImpersonationRequest,
):
    """The ``ScaleUser`` impersonation token endpoint.

    This endpoint provides authentication tokens to the front-end
    webapp in non-production mode. This allows the developer to
    provide, via POST of the json payload, the values that they want
    the returned ``ScaleUser`` token to contain.
    """
    if app_config.is_production:
        logger.error("token impersonate called in production mode")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if scale_user_request.secret_key.get_secret_value() != app_config.SECRET_KEY:
        logger.error(
            "token impersonate invalid secret key: %s",
            scale_user_request.secret_key.get_secret_value(),
        )
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "Unable to authenticate"}

    if scale_user_request.id is None:
        # We generate an id based on the provided email address. We don't use
        # the email directly so that the id remains opaque and not something
        # to be relied on for something useful.
        test_email = scale_user_request.email.encode("utf-8")
        test_id = base64.urlsafe_b64encode(test_email).strip(b"=").decode("ascii")
        scale_user_request.id = test_id + "@scale_api"

    request.session["scale_user"] = scale_user_request.session_dict()
    token = auth.create_scale_user_token(scale_user_request)
    logger.info("Return token impersonate for ScaleUser: %s", scale_user_request)
    return {
        "token": token,
    }


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
        logger.error("oauth token client not found: %s", client_id)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "invalid_client"}

    if not auth.verify_password(client_secret, auth_user.client_secret_hash):
        logger.error("oauth token invalid password AuthUser: %s", auth_user)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "invalid_client"}

    token = auth.create_auth_user_token(auth_user)
    logger.info("Return token for AuthUser: %s", auth_user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": app_config.OAUTH_ACCESS_TOKEN_EXPIRY,
    }


@router.get("/userinfo", dependencies=[Depends(auth.authorize)])
def user_info(request: Request):
    """User Info endpoint."""
    scale_user = request.session.get("scale_user")
    if scale_user is not None:
        return scale_user
    return request.state.auth_user


def verify_request(request: Request, form_token: str) -> None:
    """Verifies the CSRF form token matches the token stored in the web session."""
    csrf_token = request.session.get("csrf_token")
    if not csrf_token or form_token != csrf_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)


def build_context(request: Request) -> dict[str, Any]:
    """Provides a CSRF token for use in a template.

    Returns the CSRF token from the web session if one exists. Else
    generates a new token and sets it in the web session.
    """
    csrf_token = request.session.get("csrf_token")
    if csrf_token is None:
        request.session["csrf_token"] = csrf_token = uuid.uuid4().hex
    return {
        "app_config": app_config,
        "csrf_token": csrf_token,
    }

"""
LTI 1.3 Endpoint

This route handles the OIDC Login Initiation request from the Platform
and the Launch Request.

The Launch Request route is responsible for generating a ``ScaleUser``
that is used throughout the application.

see https://www.imsglobal.org/spec/lti/v1p3
"""
import logging
import urllib.parse
import uuid
from typing import Annotated

from authlib import jose
from authlib.oidc.core import IDToken
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

from .. import (
    db,
    keys,
    schemas,
    security,
    templates,
)
from ..lti import messages, services
from ..settings import app_config

logger = logging.getLogger(__name__)

router = APIRouter()

JWT = jose.JsonWebToken(["RS256", "RS512"])

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

LTI_TOKEN_EXPIRY = 60 * 60 * 12

ScaleUser = Annotated[schemas.ScaleUser, Depends(security.req_scale_user)]


@router.get("/{platform_id}/config")
async def lti_config(request: Request, platform_id: str):
    """Canvas LTI Configuration.

    This route provides configuration information for the Canvas LMS. When
    creating an LTI Developer Key in Canvas, the URL to this route can be
    provided in order to automate the set-up.
    """
    platform = await platform_or_404(platform_id)
    tool_url = request.url_for(lti_config.__qualname__, platform_id=platform.id)
    tool_domain = urllib.parse.urlparse(str(tool_url)).hostname
    provider_domain = urllib.parse.urlparse(platform.issuer).hostname
    tool_id = "OR2STEM"
    tool_title = "On-Ramp to STEM"
    tool_description = (
        "On-Ramp to STEM is an open-source adaptive learning technology that "
        "utilizes culturally responsive teaching pedagogy with a focus on "
        "algebra and pre-calculus because they represent important, "
        "foundational courses of the STEM pathway."
    )
    target_link_uri = request.url_for("launch_form", platform_id=platform.id)
    oidc_init_url = request.url_for("login_initiations_form", platform_id=platform.id)
    jwks_url = request.url_for("jwks")
    return {
        "title": tool_title,
        "description": tool_description,
        "oidc_initiation_url": oidc_init_url,
        "target_link_uri": target_link_uri,
        # see https://github.com/instructure/canvas-lms/blob/master/lib/token_scopes.rb
        "scopes": [
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/score",
            "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
            "https://canvas.instructure.com/lti/account_lookup/scope/show",
        ],
        "extensions": [
            {
                "domain": tool_domain,
                "tool_id": tool_id,
                "platform": provider_domain,
                "settings": {
                    "privacy_level": "public",
                    "placements": [
                        {
                            "text": tool_title,
                            "enabled": True,
                            "placement": "link_selection",
                            "message_type": "LtiResourceLinkRequest",
                            "target_link_uri": target_link_uri,
                            "selection_height": 800,
                            "selection_width": 800,
                            "custom_fields": {
                                "canvas_user_id": "$Canvas.user.id",
                                "canvas_user_login_id": "$Canvas.user.loginId",
                            },
                        },
                        {
                            "text": tool_title,
                            "enabled": True,
                            "placement": "assignment_selection",
                            "message_type": "LtiDeepLinkingRequest",
                            "target_link_uri": target_link_uri,
                            "selection_height": 800,
                            "selection_width": 800,
                            "custom_fields": {
                                "canvas_user_id": "$Canvas.user.id",
                                "canvas_user_login_id": "$Canvas.user.loginId",
                            },
                        },
                    ],
                },
            }
        ],
        "public_jwk_url": jwks_url,
        "custom_fields": {
            "canvas_user_id": "$Canvas.user.id",
            "canvas_user_login_id": "$Canvas.user.loginId",
        },
    }


@router.get("/{platform_id}/launches", include_in_schema=False)
async def launch_query(  # noqa: PLR0913
    request: Request,
    response: Response,
    platform_id: str,
    state: str,
    id_token: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """LTI Launch endpoint.

    This route is provided for compatibility only. Launch requests SHOULD
    normally be a POST request since the IDToken value can be quite large.
    """
    return await launch_form(
        request,
        response,
        platform_id,
        state,
        id_token,
        error,
        error_description,
    )


@router.post("/{platform_id}/launches")
async def launch_form(  # noqa: PLR0913
    request: Request,
    response: Response,
    platform_id: str,
    state: str = Form(...),
    id_token: str | None = Form(None),
    error: str = Form(None),
    error_description: str = Form(None),
):
    """LTI Launch endpoint.

    This handles the Launch Requests from the LMS. The LMS must have this
    ``redirect_uri`` configured and will return the user to this endpoint
    after the OIDC login initiation is performed.
    """
    logger.info(
        "[%s]: LTI Launch: platform [%r]: IDToken=[%s]", state, platform_id, id_token
    )

    if id_token is None:
        logger.error(
            "[%s]: missing IDToken: error code=[%s], description=[%s]",
            state,
            error,
            error_description,
        )
        response.status_code = status.HTTP_403_FORBIDDEN
        return {
            "error": error,
            "error_description": error_description,
            "error_state": state,
        }

    platform = await platform_or_404(platform_id)
    logger.info("[%s]: %r", state, platform)

    # Match up the state provided in the OIDC login initiation with the
    # state store in a cookie to ensure this request is associated with
    # this user-agent.
    state_cookie_key = f"lti1p3-state-{platform_id}"
    state_cookie_val = request.cookies.get(state_cookie_key)
    if state_cookie_val != state:
        logger.error(
            "[%s]: state does not match Cookie [%s]\n%r",
            state,
            state_cookie_val,
            request.headers.getlist("cookie"),
        )
    else:
        logger.info("[%s]: state matched in Cookie", state)
        response.delete_cookie(state_cookie_key)

    # Since the IDToken is being provided by the user-agent and not from
    # a direct call from our application, we MUST validate the sig.
    claims = await decode_lti_id_token(id_token, platform)

    logger.info("[%s]: IDToken claims: %r", state, claims)
    claims.validate(leeway=5)

    # To avoid replay attacks we verify the nonce provided was previously
    # stored, and then we remove from the cache so any future requests with
    # the same nonce will fail.
    nonce = claims.get("nonce")
    cached_nonce_plat = await db.cache_store.pop_async(f"lti1p3-nonce-{nonce}")
    if not cached_nonce_plat or cached_nonce_plat != platform_id:
        logger.error(
            "[%s]: nonce not found or platform not matched: %s",
            state,
            cached_nonce_plat,
        )
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            "error": "invalid_nonce",
            "error_description": "nonce not found or platform not matched",
            "error_state": state,
        }

    # At this point the IDToken (Launch Request) is valid, and we can
    # build a ``ScaleUser`` from it. We also store it for use later
    # in order to make calls to the LTI Advantage Services.
    message_launch = messages.LtiLaunchRequest(platform, claims)
    try:
        scale_user = message_launch.scale_user
    except ValueError as ve:
        logger.warning(
            "[%s]: failed to get ScaleUser from LtiLaunchRequest: %r", state, ve
        )
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            "error": "invalid_launch",
            "error_description": str(ve),
            "error_state": state,
        }

    await db.cache_store.put_async(
        message_launch.launch_id,
        message_launch.dumps(),
        ttl=LTI_TOKEN_EXPIRY,
        ttl_type=db.cache_store.TTL_TYPE_ROLLING,
    )

    # Handle Deep Linking requests separately
    if message_launch.is_deep_link_launch:
        return await deep_link_launch(request, response, message_launch)

    base_url = (
        "http://localhost:8080"
        if app_config.api.is_local
        else str(request.url_for("index_api"))
    )
    target_url = urllib.parse.urljoin(base_url, app_config.api.frontend_launch_path)
    logger.info("[%s]: redirecting via POST to v2: %s", state, target_url)
    token = security.create_scale_user_token(scale_user, expires_in=LTI_TOKEN_EXPIRY)
    response = templates.redirect_lms_auth(target_url, token)
    response.delete_cookie(state_cookie_key)
    return response


async def deep_link_launch(
    request: Request, response: Response, message_launch: messages.LtiLaunchRequest
):
    """Deep Linking Launch Requests."""
    # TODO: handle DeepLinking request Messages
    client = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    logger.error(
        "[%s]: unexpected launch type [%s]", client, message_launch.message_type
    )
    response.status_code = status.HTTP_501_NOT_IMPLEMENTED
    response.delete_cookie(f"lti1p3-state-{message_launch.platform.id}")
    return {"error": f"{message_launch.message_type} launches not implemented"}


@router.get("/{platform_id}/login_initiations", include_in_schema=False)
async def login_initiations_query(  # noqa: PLR0913
    request: Request,
    response: Response,
    platform_id: str,
    iss: str,
    login_hint: str,
    target_link_uri: str,
    lti_message_hint: str,
    lti_deployment_id: str | None = None,
    client_id: str | None = None,
):
    """LTI OIDC Login Initiation.

    Provided in order to support either GET or POST requests. This delegates
    to the POST launch endpoint.
    """
    return await login_initiations_form(
        request,
        response,
        platform_id,
        iss,
        login_hint,
        target_link_uri,
        lti_message_hint,
        lti_deployment_id,
        client_id,
    )


@router.post("/{platform_id}/login_initiations")
async def login_initiations_form(  # noqa: PLR0913
    request: Request,
    response: Response,
    platform_id: str,
    iss: str = Form(...),
    login_hint: str = Form(...),
    target_link_uri: str = Form(...),
    lti_message_hint: str = Form(...),
    lti_deployment_id: str = Form(None),
    client_id: str = Form(None),
):
    """LTI OIDC Login Initiation.

    LTI 1.3 uses a modified version of OIDC 3rd Party Login Initiation. The
    URL is ``Platform`` specific in order to work with multiple configured
    platforms.
    """

    # used as a unique transaction key to associate the launch with the
    # user-agent (browser) and in log messages to associate the client in
    # log messages here and in the launch endpoint.
    state = uuid.uuid4().hex

    client_host = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    logger.info(
        "[%s]: LTI Login Init: client=[%s], user-agent=[%s]",
        state,
        client_host,
        request.headers.get("user-agent"),
    )

    platform = await platform_or_404(platform_id)
    logger.info(
        "[%s]: iss=%s, login_hint=%s, target_link_uri=%s, "
        "lti_message_hint=%s, lti_deployment_id=%s, client_id=%s",
        state,
        iss,
        login_hint,
        target_link_uri,
        lti_message_hint,
        lti_deployment_id,
        client_id,
    )

    if platform.issuer != iss:
        logger.error(
            "[%s]: request issuer [%s] does not match Platform [%s]",
            state,
            iss,
            platform.issuer,
        )
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            "error": "invalid_request_object",
            "error_description": "Invalid issuer",
            "error_state": state,
        }

    if client_id and client_id != platform.client_id:
        logger.error(
            "[%s]: request client_id [%s] does not match Platform [%s]",
            state,
            client_id,
            platform.client_id,
        )
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            "error": "invalid_request_object",
            "error_description": "Invalid client_id",
            "error_state": state,
        }

    expect_target_uri = request.url_for("launch_form", platform_id=platform_id)
    if expect_target_uri != target_link_uri:
        logger.error(
            "[%s]: request target_link_uri [%s] does not match Platform [%s]",
            state,
            target_link_uri,
            expect_target_uri,
        )
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            "error": "invalid_request_object",
            "error_description": "Invalid target_link_uri",
            "error_state": state,
        }

    nonce = uuid.uuid4().hex  # prevent replay attacks
    await db.cache_store.put_async(f"lti1p3-nonce-{nonce}", platform_id, ttl=120)
    query_string = {
        # only supported type is id_token
        "response_type": "id_token",
        # the url registered with the platform
        "redirect_uri": target_link_uri,
        # since the id_token can be large we ask that it be sent in a POST
        "response_mode": "form_post",
        # client_id provided when our app was registered with the platform
        "client_id": platform.client_id,
        # must include ``openid``, does not appear any other OIDC scopes such as
        # ``email`` or ``profile`` can be specified here (at least for Canvas)
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        # since the launch is initiated from the platform and the user is
        # already authenticated there
        "prompt": "none",
    }

    # Per the spec, if ``login_hint`` or ``lti_message_hint`` were provided
    # then they need to be included in the request.

    if login_hint:
        query_string["login_hint"] = login_hint

    if lti_message_hint:
        query_string["lti_message_hint"] = lti_message_hint

    encoded_query_string = urllib.parse.urlencode(query_string)
    target_url = urllib.parse.urljoin(
        str(platform.oidc_auth_url), "?" + encoded_query_string
    )

    response = RedirectResponse(
        url=target_url,
        headers={
            **NO_CACHE_HEADERS,
            "X-Frame-Options": "DENY",
        },
        status_code=status.HTTP_302_FOUND,
    )

    response.set_cookie(
        f"lti1p3-state-{platform_id}",
        state,
        max_age=600,
        secure=True,
        httponly=True,
        samesite="none",
    )

    logger.info("[%s]: redirecting to %s", state, target_url)
    return response


@router.get(
    "/members",
    response_model=list[schemas.ScaleUser],
    response_model_exclude_unset=True,
    dependencies=[Security(security.authorize)],
)
async def names_role_service(scale_user: ScaleUser):
    # If launched from the console or from an impersonation token we won't
    # have an LTI service to call, so we take a different path.
    if scale_user.platform_id == "scale_api":
        return []

    launch_id = messages.LtiLaunchRequest.launch_id_for(scale_user)
    logger.info("Loading launch message [%s] for ScaleUser: %s", launch_id, scale_user)
    cached_launch = await db.cache_store.get_async(launch_id)
    # TODO: what if `cached_launch` is None?
    launch_request = messages.LtiLaunchRequest.loads(cached_launch)  # type: ignore
    if not launch_request.is_instructor:
        logger.error("lti.members unauthorized request from ScaleUser: %s", scale_user)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    nrps = services.NamesRoleService(launch_request)
    members = await nrps.members()
    return [
        schemas.ScaleUser(id=m["user_id"] + "@" + launch_request.platform.id, **m)
        for m in members
        if m.get("email")
    ]


async def platform_or_404(platform_id: str) -> schemas.Platform:
    """Returns a ``Platform``, else HTTP 404 if one is not found for the id."""
    try:
        return await db.store.platform_async(platform_id)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Platform {platform_id} not found",
        ) from None


async def decode_lti_id_token(
    id_token: str,
    platform: schemas.Platform,
) -> jose.JWTClaims:
    # Some basic jwt claims validation options
    id_token_opts = {
        "iss": {"essential": True, "value": platform.issuer},
        "aud": {"essential": True, "value": platform.client_id},
        "nonce": {"essential": True},
    }
    key_set = await keys.get_jwks_from_url(platform.jwks_url)
    try:
        return JWT.decode(
            id_token,
            key_set,
            claims_cls=IDToken,
            claims_options=id_token_opts,
        )
    except jose.errors.KeyMismatchError:
        key_set = await keys.get_jwks_from_url(platform.jwks_url, use_cache=False)
        return JWT.decode(
            id_token,
            key_set,
            claims_cls=IDToken,
            claims_options=id_token_opts,
        )

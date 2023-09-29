"""
LTI 1.3 Endpoint

This route handles the OIDC Login Initiation request from the Platform
and the Launch Request.

The Launch Request route is responsible for generating a ``ScaleUser``
that is used throughout the application.

see https://www.imsglobal.org/spec/lti/v1p3
"""
import asyncio
import hashlib
import logging
import urllib.parse
from typing import Annotated, Any

import joserfc.errors
import joserfc.jwt
import shortuuid
from fastapi import (
    APIRouter,
    Depends,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, RedirectResponse

from .. import (
    db,
    keys,
    security,
    services,
    settings,
    templates,
)
from ..schemas import (
    LineItem,
    LtiLaunchRequest,
    LtiServiceError,
    Platform,
    ScaleGrade,
    ScaleUser,
    Score,
)

logger = logging.getLogger(__name__)

router = APIRouter()

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

LTI_TOKEN_EXPIRY = 60 * 60 * 24 * 7  # 1 week
AGS_CACHE_EXPIRY = 60 * 60 * 24 * 60  # 60 days

User = Annotated[ScaleUser, Depends(security.req_scale_user)]


@router.get("/{platform_id}/config")
async def lti_config(request: Request, platform_id: str) -> dict[str, Any]:
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
        "oidc_initiation_url": str(oidc_init_url),
        "target_link_uri": str(target_link_uri),
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
                            "target_link_uri": str(target_link_uri),
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
                            "target_link_uri": str(target_link_uri),
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
        "public_jwk_url": str(jwks_url),
        "custom_fields": {
            "canvas_user_id": "$Canvas.user.id",
            "canvas_user_login_id": "$Canvas.user.loginId",
        },
    }


@router.get("/{platform_id}/launches", include_in_schema=False)
async def launch_query(
    request: Request,
    response: Response,
    platform_id: str,
    state: str,
    id_token: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> Response:
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


@router.post("/{platform_id}/launches", include_in_schema=False)
async def launch_form(
    request: Request,
    response: Response,
    platform_id: str,
    state: str = Form(...),
    id_token: str | None = Form(None),
    error: str | None = Form(None),
    error_description: str | None = Form(None),
) -> Response:
    """LTI Launch endpoint.

    This handles the Launch Requests from the LMS. The LMS must have this
    ``redirect_uri`` configured and will return the user to this endpoint
    after the OIDC login initiation is performed.
    """
    logger.info("LTI Launch: state [%s], platform [%s]", state, platform_id)
    logger.debug("IDToken=[%s]", id_token)

    if id_token is None:
        logger.error(
            "missing IDToken: error code=[%s], description=[%s]",
            error,
            error_description,
        )
        content = {
            "error": error,
            "error_description": error_description,
            "error_state": state,
        }
        return JSONResponse(content=content, status_code=status.HTTP_403_FORBIDDEN)

    platform = await platform_or_404(platform_id)

    # Match up the state provided in the OIDC login initiation with the
    # state store in a cookie to ensure this request is associated with
    # this user-agent.
    state_cookie_key = f"lti1p3-state-{platform_id}"
    state_cookie_val = request.cookies.get(state_cookie_key)
    if state_cookie_val != state:
        logger.error(
            "state [%s] does not match Cookie [%s]",
            state,
            state_cookie_val,
        )
    else:
        response.delete_cookie(state_cookie_key)

    claims = await decode_lti_id_token(id_token, platform)

    # To avoid replay attacks we verify the nonce provided was previously
    # stored, and then we remove from the cache so any future requests with
    # the same nonce will fail.
    nonce = claims.get("nonce")
    cached_nonce_plat = await db.store.cache_pop(key=f"lti1p3-nonce-{nonce}")
    if not cached_nonce_plat or cached_nonce_plat != platform_id:
        logger.error("nonce not found or platform not matched: %s", cached_nonce_plat)
        content = {
            "error": "invalid_nonce",
            "error_description": "nonce not found or platform not matched",
            "error_state": state,
        }
        return JSONResponse(content=content, status_code=status.HTTP_400_BAD_REQUEST)

    # At this point the IDToken (Launch Request) is valid, and we can
    # build a ``ScaleUser`` from it. We also store it for use later
    # in order to make calls to the LTI Advantage Services.
    message_launch = LtiLaunchRequest(platform, claims)
    try:
        scale_user = message_launch.scale_user
        logger.info("launch for %r", scale_user)
    except ValueError as ve:
        logger.warning("failed to get ScaleUser from LtiLaunchRequest: %r", ve)
        content = {
            "error": "invalid_launch",
            "error_description": str(ve),
            "error_state": state,
        }
        return JSONResponse(content=content, status_code=status.HTTP_400_BAD_REQUEST)

    await db.store.cache_put(
        key=message_launch.launch_id,
        value=message_launch.dumps(),
        ttl=LTI_TOKEN_EXPIRY,
        ttl_type=db.store.CACHE_TTL_TYPE_ROLLING,
    )

    # Handle Deep Linking requests separately
    if message_launch.is_deep_link_launch:
        return await deep_link_launch(request, message_launch)

    base_url = str(request.url_for("index_api"))
    target_url = urllib.parse.urljoin(base_url, settings.api.frontend_launch_path)
    logger.info("redirecting via POST to v2: %s", target_url)
    token = security.create_scale_user_token(scale_user, expires_in=LTI_TOKEN_EXPIRY)
    logger.info("Launch ID %s", message_launch.launch_id)
    logger.info("Launch Token [%s]", token)
    response = templates.redirect_lms_auth(target_url, token)
    response.delete_cookie(state_cookie_key)
    return response


@router.get("/{platform_id}/login_initiations", include_in_schema=False)
async def login_initiations_query(
    request: Request,
    platform_id: str,
    iss: str,
    login_hint: str,
    target_link_uri: str,
    lti_message_hint: str,
    lti_deployment_id: str | None = None,
    client_id: str | None = None,
) -> Response:
    """LTI OIDC Login Initiation.

    Provided in order to support either GET or POST requests. This delegates
    to the POST launch endpoint.
    """
    return await login_initiations_form(
        request,
        platform_id,
        iss,
        login_hint,
        target_link_uri,
        lti_message_hint,
        lti_deployment_id,
        client_id,
    )


@router.post("/{platform_id}/login_initiations", include_in_schema=False)
async def login_initiations_form(
    request: Request,
    platform_id: str,
    iss: str = Form(...),
    login_hint: str = Form(...),
    target_link_uri: str = Form(...),
    lti_message_hint: str = Form(...),
    lti_deployment_id: str | None = Form(None),
    client_id: str | None = Form(None),
) -> Response:
    """LTI OIDC Login Initiation.

    LTI 1.3 uses a modified version of OIDC 3rd Party Login Initiation. The
    URL is ``Platform`` specific in order to work with multiple configured
    platforms.
    """

    # used as a unique transaction key to associate the launch with the
    # user-agent (browser) and in log messages to associate the client in
    # log messages here and in the launch endpoint.
    state = settings.ctx_request.get().request_id

    platform = await platform_or_404(platform_id)
    logger.info(
        "LTI Login Init: iss=%s, login_hint=%s, target_link_uri=%s, "
        "lti_message_hint=%s, lti_deployment_id=%s, client_id=%s",
        iss,
        login_hint,
        target_link_uri,
        lti_message_hint,
        lti_deployment_id,
        client_id,
    )

    if platform.issuer != iss:
        logger.error(
            "request issuer [%s] does not match Platform [%s]",
            iss,
            platform.issuer,
        )
        content = {
            "error": "invalid_request_object",
            "error_description": "Invalid issuer",
            "error_state": state,
        }
        return JSONResponse(content=content, status_code=status.HTTP_400_BAD_REQUEST)

    if client_id and client_id != platform.client_id:
        logger.error(
            "request client_id [%s] does not match Platform [%s]",
            client_id,
            platform.client_id,
        )
        content = {
            "error": "invalid_request_object",
            "error_description": "Invalid client_id",
            "error_state": state,
        }
        return JSONResponse(content=content, status_code=status.HTTP_400_BAD_REQUEST)

    expect_target_uri = request.url_for("launch_form", platform_id=platform_id)
    if expect_target_uri != target_link_uri:
        logger.error(
            "request target_link_uri [%s] does not match Platform [%s]",
            target_link_uri,
            expect_target_uri,
        )
        content = {
            "error": "invalid_request_object",
            "error_description": "Invalid target_link_uri",
            "error_state": state,
        }
        return JSONResponse(content=content, status_code=status.HTTP_400_BAD_REQUEST)

    nonce = shortuuid.uuid()  # prevent replay attacks
    await db.store.cache_put(
        key=f"lti1p3-nonce-{nonce}",
        value=platform_id,
        ttl=120,
    )
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

    logger.info("redirecting to %s", target_url)
    return response


@router.get("/members", response_model_exclude_unset=True)
async def nrps_members(user: User, next_token: str | None = None) -> dict[str, Any]:
    # If launched from the console or from an impersonation token we won't
    # have an LTI service to call, so we take a different path.
    if user.platform_id == "scale_api":
        logger.warning("names_role_service(%r): no LMS context", user)
        return {"next_token": None, "members": [user]}

    launch_id = LtiLaunchRequest.launch_id_for(user)
    logger.info("Loading launch message [%s] for ScaleUser: %s", launch_id, user)
    cached_launch = await db.store.cache_get(key=launch_id)
    if cached_launch is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="LTI Launch Message not found",
        )
    launch_request = LtiLaunchRequest.loads(cached_launch)
    if not launch_request.is_instructor:
        logger.error("lti.members unauthorized request: %s", launch_request.scale_user)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    nrps_client = services.NamesRoleService(launch_request)
    result = await nrps_client.members(next_page_url=next_token)
    return {
        "next_token": result.next_page,
        "context": result.context,
        "members": [
            ScaleUser(id=m["user_id"] + "@" + launch_request.platform.id, **m)
            for m in result.members
            if m.get("email")
        ],
    }


@router.post("/scores", status_code=status.HTTP_201_CREATED)
async def ags_grades(
    user: User, grade: ScaleGrade, x_api_key: Annotated[str, Header()]
) -> None:
    if x_api_key != settings.api.frontend_api_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    logger.debug("assignment_grade_service: %r - %r", user, grade)
    launch_id = LtiLaunchRequest.launch_id_for(user)
    if not (cached_request := await db.store.cache_get(key=launch_id)):
        msg = f"Launch Request [{launch_id}] not found in cache"
        logger.warning(msg)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)

    launch_request = LtiLaunchRequest.loads(cached_request)
    validate_grade(grade, launch_request)

    score = Score.model_validate(
        {
            "timestamp": grade.timestamp,
            "scoreGiven": grade.score,
            "scoreMaximum": grade.scoremax,
            "userId": grade.lms_user_id,
        }
    )

    service = services.AssignmentGradeService(launch_request)

    # in case of multiple submissions for the same assignment (lineitem),
    # need to allow for retrying this request
    for i in range(3):
        if i != 0:
            await asyncio.sleep((0.5 + i) * 2.0)
        if item := await get_or_create_lineitem(service, grade, launch_request):
            try:
                await service.add_score(item, score)
            except LtiServiceError as exc:
                raise HTTPException(
                    status_code=exc.status_code, detail=exc.message
                ) from None
            return

    raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS)


async def platform_or_404(platform_id: str) -> Platform:
    """Returns a ``Platform``, else HTTP 404 if one is not found for the id."""
    try:
        return await db.store.platform(platform_id=platform_id)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Platform {platform_id} not found",
        ) from None


async def decode_lti_id_token(id_token: str, platform: Platform) -> joserfc.jwt.Claims:
    if platform.jwks_url is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"No JWKS URL set for Platform {platform.id}",
        )
    # Since the IDToken is being provided by the user-agent and not from
    # a direct call from our application, we MUST validate the sig.
    key_set = await keys.jwks_from_url(str(platform.jwks_url))
    try:
        jwt_token = joserfc.jwt.decode(
            value=id_token,
            key=key_set,
            algorithms=["RS256", "RS512"],
        )
    except joserfc.errors.InvalidEncryptedKeyError:
        key_set = await keys.jwks_from_url(str(platform.jwks_url), use_cache=False)
        jwt_token = joserfc.jwt.decode(
            value=id_token,
            key=key_set,
            algorithms=["RS256", "RS512"],
        )

    claims = jwt_token.claims
    logger.debug("IDToken claims: %r", claims)
    # Some basic jwt claims validation options
    id_token_opts: dict[str, joserfc.jwt.ClaimsOption] = {
        "iss": {"essential": True, "value": platform.issuer or ""},
        "aud": {"essential": True, "value": platform.client_id or ""},
        "nonce": {"essential": True},
    }
    joserfc.jwt.JWTClaimsRegistry(now=None, leeway=5, **id_token_opts).validate(claims)
    return claims


async def deep_link_launch(
    request: Request, message_launch: LtiLaunchRequest
) -> Response:
    """Deep Linking Launch Requests."""
    # TODO: handle DeepLinking request Messages
    client = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    logger.error(
        "[%s]: unexpected launch type [%s]", client, message_launch.message_type
    )
    response = JSONResponse(
        content={"error": f"{message_launch.message_type} launches not implemented"},
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
    )
    response.delete_cookie(f"lti1p3-state-{message_launch.platform.id}")
    return response


def validate_grade(grade: ScaleGrade, launch_request: LtiLaunchRequest) -> None:
    if grade.platform_id != launch_request.platform.id:
        details = {
            "code": "invalid_platform",
            "message": (
                f"{grade.platform_id} for user does not match"
                f" platform of the Launch Request: {launch_request.platform.id}"
            ),
        }
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=details)

    if grade.courseid != launch_request.context["id"]:
        details = {
            "code": "invalid_courseid",
            "message": (
                f"{grade.courseid} does not match context from Launch Request: "
                f"{launch_request.context['id']}"
            ),
        }
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=details)


async def get_or_create_lineitem(
    service: services.AssignmentGradeService,
    grade: ScaleGrade,
    launch_request: LtiLaunchRequest,
) -> LineItem | None:
    if item := await service.lineitem(grade.chapter):
        return item

    # must ensure lineitem is only created once, use the cache table as a
    # multiprocess lock
    item = LineItem.model_validate(
        {"scoreMaximum": grade.scoremax, "label": grade.chapter}
    )
    hasher = hashlib.sha1(grade.chapter.lower().encode(encoding="utf-8"))  # noqa: S324
    li_key = (
        "lti-lineitem-"
        f"{launch_request.platform.id}-{launch_request.context['id']}-"
        f"{hasher.hexdigest()}"
    )
    cache_key = await db.store.cache_add(
        key=li_key, value=item.model_dump_json(), ttl=AGS_CACHE_EXPIRY
    )
    if cache_key is None:
        logger.warning("another process is adding %r", item)
        return None

    return await service.add_lineitem(item)

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
from typing import List

from authlib import jose
from authlib.oidc.core import IDToken
from fastapi import (
    APIRouter,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    Security,
    status,
)
from fastapi.responses import RedirectResponse

from scale_api import (
    app_config,
    auth,
    db,
    keys,
    settings,
    schemas,
    templates,
)
from scale_api.lti import (
    messages,
    services,
)

logger = logging.getLogger(__name__)

router = APIRouter()

JWT = jose.JsonWebToken(['RS256', 'RS512'])


@router.get('/', include_in_schema=False)
async def lti_home(request: Request):
    context = {
        'scale_user': request.session['scale_user'],
        'scale_env': app_config.ENV,
    }
    return templates.render(request, 'lti.html', context)


@router.get('/{platform_id}/config')
async def lti_config(request: Request, platform_id: str):
    """Canvas LTI Configuration.

    This route provides configuration information for the Canvas LMS. When
    creating a LTI Developer Key in Canvas, the URL to this route can be
    provided in order to automate the set up.
    """
    platform = await platform_or_404(platform_id)
    tool_url = request.url_for(lti_config.__qualname__, platform_id=platform.id)
    tool_domain = urllib.parse.urlparse(tool_url).hostname
    provider_domain = urllib.parse.urlparse(platform.issuer).hostname
    tool_id = 'OR2STEM'
    tool_title = 'On-Ramp to STEM'
    tool_description = (
        'On-Ramp to STEM is an open-source adaptive learning technology that '
        'utilizes culturally responsive teaching pedagogy with a focus on '
        'algebra and pre-calculus because they represent important, '
        'foundational courses of the STEM pathway.'
    )
    target_link_uri = request.url_for('launch_form', platform_id=platform.id)
    oidc_init_url = request.url_for('login_initiations_form', platform_id=platform.id)
    jwks_url = request.url_for('jwks')
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
                    ]
                }
            }
        ],
        "public_jwk_url": jwks_url,
        "custom_fields": {
            "canvas_user_id": "$Canvas.user.id",
            "canvas_user_login_id": "$Canvas.user.loginId",
        }
    }


@router.get('/{platform_id}/launches', include_in_schema=False)
async def launch_query(
        request: Request,
        response: Response,
        platform_id: str,
        state: str = Query(...),
        id_token: str = Query(None),
        error: str = Query(None),
        error_description: str = Query(None),
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


@router.post('/{platform_id}/launches')
async def launch_form(
        request: Request,
        response: Response,
        platform_id: str,
        state: str = Form(...),
        id_token: str = Form(None),
        error: str = Form(None),
        error_description: str = Form(None),
):
    """LTI Launch endpoint.

    This handles the Launch Requests from the LMS. The LMS must have this
    ``redirect_uri`` configured and will return the user to this endpoint
    after the OIDC login initiation is performed.
    """
    # Always expect an IDToken
    if id_token is None:
        logger.error('Error code: %s, description: %s',
                     error, error_description)
        return {'error': error, 'error_description': error_description}

    platform = await platform_or_404(platform_id)
    logger.info('id_token: %s, %s', id_token, platform)

    # Match up the state provided in the OIDC login initiation with the
    # state store in a cookie to ensure this request is associated with
    # this user-agent.
    state_cookie = request.cookies.get(f'lti1p3-state-{platform_id}')
    if state_cookie != state:
        logger.error('State cookie value [%s] does not match state [%s]',
                     state_cookie, state)
        return {'error': 'invalid_state'}

    # Some basic jwt claims validation options
    id_token_opts = {
        'iss': {
            'essential': True,
            'value': platform.issuer
        },
        'aud': {
            'essential': True,
            'value': platform.client_id
        },
        'nonce': {
            'essential': True,
        }
    }

    # Since the IDToken is being provided by the user-agent and not from
    # a direct call from our application, we MUST validate the sig.
    # TODO - handle case where we need to re-fetch the jwks url
    key_set = await keys.get_jwks_from_url(platform.jwks_url)
    claims = JWT.decode(id_token, key_set, claims_cls=IDToken, claims_options=id_token_opts)
    logger.info(claims)
    claims.validate(leeway=5)

    # To avoid replay attacks we verify the nonce provided was previously
    # stored and then we remove from the cache so any future requests with
    # the same nonce will fail.
    nonce = claims.get('nonce')
    cached_nonce_plat = await db.cache_store.pop_async(f'lti1p3-nonce-{nonce}')
    if not cached_nonce_plat or cached_nonce_plat != platform_id:
        logger.error('Nonce not found or platform not matched: %s',
                     cached_nonce_plat)
        return {'error': 'invalid_nonce'}

    # At this point the IDToken (Launch Request) is valid and we can
    # build a ``ScaleUser`` from it. We also store it for use later
    # in order to make calls to the LTI Advantage Services.
    message_launch = messages.LtiLaunchRequest(platform, claims)
    scale_user = message_launch.scale_user

    # Check to see whether user already has a launch from another context
    if session_scale_user := request.session.get('scale_user'):
        logger.warning('User has existing launch: ScaleUser(%s)',
                       session_scale_user)
        session_scale_user = schemas.ScaleUser(**session_scale_user)
        if (
                session_scale_user.id != scale_user.id or
                session_scale_user.context != scale_user.context
        ):
            logger.error('Aborting attempt to launch for a different context'
                         'Session: %s, Launch: %s',
                         session_scale_user.context, scale_user.context)
            return {
                'error': 'invalid_request',
                'error_description': 'Attempting to launch for a different context',
            }

    logger.info('Adding scale_user to session: %s', scale_user)
    request.session['scale_user'] = scale_user.session_dict()

    await db.cache_store.put_async(
        message_launch.launch_id,
        message_launch.dumps(),
        ttl=3600,
        ttl_type=db.cache_store.TTL_TYPE_ROLLING,
    )

    # Handle Deep Linking requests separately
    if message_launch.is_deep_link_launch:
        return await deep_link_launch(request, response, message_launch)

    # From here we just need to determine where to send the user in
    # order to being using the SCALE app.

    if app_config.is_local:
        base_url = 'http://localhost:8080'
    else:
        base_url = request.url_for('lti_home')

    if app_config.is_production:
        course_path = '/question-editor/'
    elif app_config.is_local:
        course_path = '/'
    else:
        course_path = f'/{app_config.ENV}/question-editor/'

    target_url = urllib.parse.urljoin(base_url, course_path)
    logger.info('Redirecting to %s', target_url)
    response = RedirectResponse(
        target_url,
        headers=settings.NO_CACHE_HEADERS,
        status_code=status.HTTP_302_FOUND
    )
    response.delete_cookie(f'lti1p3-state-{platform_id}')
    return response


async def deep_link_launch(
        request: Request,
        response: Response,
        message_launch: messages.LtiLaunchRequest
):
    """Deep Linking Launch Requests."""
    # TODO: handle DeepLinking request Messages
    response.delete_cookie(f'lti1p3-state-{message_launch.platform.id}')
    return {'error': f'{message_launch.message_type} launches not implemented'}


@router.get('/{platform_id}/login_initiations', include_in_schema=False)
async def login_initiations_query(
        request: Request,
        response: Response,
        platform_id: str,
        iss: str = Query(...),
        login_hint: str = Query(...),
        target_link_uri: str = Query(...),
        lti_message_hint: str = Query(...),
        lti_deployment_id: str = Query(None),
        client_id: str = Query(None),

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


@router.post('/{platform_id}/login_initiations')
async def login_initiations_form(
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
    platform = await platform_or_404(platform_id)
    logger.info('login_initiations(iss=%s, login_hint=%s, target_link_uri=%s, '
                'lti_message_hint=%s, lti_deployment_id=%s, client_id=%s)',
                iss, login_hint, target_link_uri, lti_message_hint,
                lti_deployment_id, client_id)

    if platform.issuer != iss:
        logger.error('Request issuer [%s] does not match Platform [%s]',
                     iss, platform.issuer)
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            'error': 'invalid_request_object',
            'error_description': 'Invalid issuer'
        }

    if client_id and client_id != platform.client_id:
        logger.error('Request client_id [%s] does not match Platform [%s]',
                     client_id, platform.client_id)
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            'error': 'invalid_request_object',
            'error_description': 'Invalid client_id'
        }

    expect_target_uri = request.url_for('launch_form', platform_id=platform_id)
    if expect_target_uri != target_link_uri:
        logger.error('Request target_link_uri [%s] does not match Platform [%s]',
                     target_link_uri, expect_target_uri)
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {
            'error': 'invalid_request_object',
            'error_description': 'Invalid target_link_uri'
        }

    state = uuid.uuid4().hex  # associate launch with the user-agent (browser)
    nonce = uuid.uuid4().hex  # prevent replay attacks
    await db.cache_store.put_async(f'lti1p3-nonce-{nonce}', platform_id, ttl=120)
    query_string = {
        # only supported type is id_token
        'response_type': 'id_token',
        # the url registered with the platform
        'redirect_uri': target_link_uri,
        # since the id_token can be large we ask that it be POST'd
        'response_mode': 'form_post',
        # client_id provided when our app was registered with the platform
        'client_id': platform.client_id,
        # must include ``openid``, does not appear any other OIDC scopes such as
        # ``email`` or ``profile`` can be specified here (at least for Canvas)
        'scope': 'openid',
        'state': state,
        'nonce': nonce,
        # since the launch is initiated from the platform and the user is
        # already authenticated there
        'prompt': 'none',
    }

    # Per the spec, if ``login_hint`` or ``lti_message_hint`` were provided
    # then they need to be included in the request.

    if login_hint:
        query_string['login_hint'] = login_hint

    if lti_message_hint:
        query_string['lti_message_hint'] = lti_message_hint

    encoded_query_string = urllib.parse.urlencode(query_string)
    target_url = urllib.parse.urljoin(str(platform.oidc_auth_url), '?' + encoded_query_string)

    response = RedirectResponse(
        url=target_url,
        headers={
            **settings.NO_CACHE_HEADERS,
            'X-Frame-Options': 'DENY',
        },
        status_code=status.HTTP_302_FOUND
    )

    response.set_cookie(
        f'lti1p3-state-{platform_id}',
        state,
        max_age=120,
        secure=True,
        samesite='none',
    )

    logger.info('Redirecting to %s', target_url)
    return response


@router.get(
    '/members',
    response_model=List[schemas.ScaleUser],
    response_model_exclude_unset=True,
    dependencies=[Security(auth.authorize)],
)
async def names_role_service(request: Request):
    scale_user = request.state.scale_user
    launch_id = messages.LtiLaunchRequest.launch_id_for(scale_user)
    logger.info('Loading launch message [%s] for ScaleUser: %s',
                launch_id, scale_user)
    cached_launch = await db.cache_store.get_async(launch_id)
    launch_request = messages.LtiLaunchRequest.loads(cached_launch)
    if not launch_request.is_instructor:
        logger.error('lti.members unauthorized request from ScaleUser: %s',
                     scale_user)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    nrps = services.NamesRoleService(launch_request)
    members = await nrps.members()
    return [
        schemas.ScaleUser(
            id=m['user_id'] + '@' + launch_request.platform.id,
            **m
        )
        for m in members if m.get('email')
    ]


async def platform_or_404(platform_id: str) -> schemas.Platform:
    """Returns a ``Platform``, else an HTTP 404 if one is not found for the id."""
    try:
        return await db.store.platform_async(platform_id)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Platform {platform_id} not found'
        )

import base64
import hashlib
import logging
import secrets
import time
import urllib.parse
from typing import Union

from authlib import jose
from authlib.oidc.core import IDToken
from fastapi import APIRouter, Form, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

import scale_api
from scale_api import (
    app_config,
    db,
    keys,
    settings,
    schemas,
    urls,
)

logger = logging.getLogger(__name__)

router = APIRouter()

JWT = jose.JsonWebToken(['RS256', 'RS512'])


@router.get('/', include_in_schema=False)
async def lti_home(request: Request):
    return request.session


@router.get('/{platform_id}/config')
async def lti_config(request: Request, platform_id: str):
    platform = await platform_or_404(platform_id)
    tool_url = request.url_for(lti_config.__qualname__, platform_id=platform.id)
    tool_url, _ = urls.parse(tool_url)
    provider_url, _ = urls.parse(platform.issuer)
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
        "scopes": [
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/score",
            "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
        ],
        "extensions": [
            {
                "domain": tool_url.hostname,
                "tool_id": tool_id,
                "platform": provider_url.hostname,
                "settings": {
                    "privacy_level": "public",
                    "placements": [
                        {
                            "text": f"{tool_title} Link Selection",
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
                            "text": f"{tool_title} Assignment Selection",
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
        platform_id: str,
        state: str = Query(...),
        id_token: str = Query(None),
        error: str = Query(None),
        error_description: str = Query(None),
):
    return await launch_form(
        request,
        platform_id,
        state,
        id_token,
        error,
        error_description
    )


@router.post('/{platform_id}/launches')
async def launch_form(
        request: Request,
        platform_id: str,
        state: str = Form(...),
        id_token: str = Form(None),
        error: str = Form(None),
        error_description: str = Form(None),
):
    if id_token is None:
        logger.error('Error code: %s, description: %s',
                     error, error_description)
        return {'error': error, 'description': error_description}

    platform = await platform_or_404(platform_id)
    logger.info('id_token: %s, %s', id_token, platform)
    logger.info('state: %s, %s', state, platform)
    session_nonce = request.cookies[f'launch-{platform_id}']
    compare_nonce = sha256(session_nonce)
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
            'value': session_nonce,
        }
    }
    # TODO - handle case where we need to re-fetch the jwks url
    key_set = await keys.get_jwks_from_url(platform.jwks_url)
    claims = JWT.decode(id_token, key_set, claims_cls=IDToken, claims_options=id_token_opts)
    claims.validate(leeway=5)
    hashed_nonce = claims.get('nonce')
    assert compare_nonce == hashed_nonce, f"{compare_nonce=} != {hashed_nonce=}"
    # TODO: compare state target uri with something
    state_token_opts = {
        'iss': {
            'essential': True,
            'value': platform.issuer
        },
        'uri': {
            'essential': True,
        },
    }
    jwt_key = f'{session_nonce}:{app_config.SECRET_KEY}'
    state_token = jose.jwt.decode(state, jwt_key, claims_options=state_token_opts)
    state_token.validate(leeway=5)
    logger.info(claims)
    # TODO: determine where to redirect based on IDToken context
    # TODO: how to associate context with question/quiz/course in scale?
    lti_context = schemas.LtiContext.from_id_token(claims)
    logger.error(lti_context)
    session_key = f'{lti_context.id}/{lti_context.resource_link.id}'
    if deploy_id := lti_context.deployment_id:
        session_key += f'/{deploy_id}'
    request.session[session_key] = lti_context.dict(exclude_unset=True, exclude_none=True)
    response = RedirectResponse(
        request.url_for('lti_home'),
        headers=settings.NO_CACHE_HEADERS,
        status_code=status.HTTP_302_FOUND
    )
    response.delete_cookie(key=f'launch-{platform_id}')
    return response


@router.get('/{platform_id}/login_initiations', include_in_schema=False)
async def login_initiations_query(
        request: Request,
        platform_id: str,
        iss: str = Query(...),
        login_hint: str = Query(...),
        target_link_uri: str = Query(...),
        lti_message_hint: str = Query(...),
        lti_deployment_id: str = Query(None),
        client_id: str = Query(None),

):
    return await login_initiations_form(
        request,
        platform_id,
        iss,
        login_hint,
        target_link_uri,
        lti_message_hint,
        lti_deployment_id,
        client_id
    )


@router.post('/{platform_id}/login_initiations')
async def login_initiations_form(
        request: Request,
        platform_id: str,
        iss: str = Form(...),
        login_hint: str = Form(...),
        target_link_uri: str = Form(...),
        lti_message_hint: str = Form(...),
        lti_deployment_id: str = Form(None),
        client_id: str = Form(None),
):
    platform = await platform_or_404(platform_id)
    logger.info(platform)
    logger.info('iss: %s, login_hint: %s, target_link_uri: %s, lti_message_hint: %s',
                iss, login_hint, target_link_uri, lti_message_hint)
    logger.info('lti_deployment_id: %s, client_id: %s',
                lti_deployment_id, client_id)
    assert platform.issuer == iss
    assert client_id is None or client_id == platform.client_id
    # TODO - validate target_link_uri
    jwt_header = {'alg': 'HS256', 'type': 'JWT'}
    jwt_state = {'iss': iss, 'uri': target_link_uri, 'exp': time.time() + 60}
    nonce = secrets.token_urlsafe(32)
    hashed_nonce = sha256(nonce)
    jwt_key = f'{nonce}:{scale_api.app_config.SECRET_KEY}'
    state = jose.jwt.encode(jwt_header, jwt_state, jwt_key)
    query_string = {
        'response_type': 'id_token',
        'redirect_uri': target_link_uri,
        'response_mode': 'form_post',
        'client_id': platform.client_id,
        'scope': 'openid',
        'state': state,
        'login_hint': login_hint,
        'lti_message_hint': lti_message_hint,
        'nonce': hashed_nonce,
        'prompt': 'none',
    }
    oidc_auth_req_url = platform.oidc_auth_url
    encoded_query_string = urllib.parse.urlencode(query_string)
    target_url = f'{oidc_auth_req_url}?{encoded_query_string}'
    response = RedirectResponse(
        target_url,
        headers=settings.NO_CACHE_HEADERS,
        status_code=status.HTTP_302_FOUND
    )
    response.set_cookie(
        key=f'launch-{platform_id}',
        value=nonce,
        secure=True,
        httponly=True,
        samesite='none',
        max_age=180,
    )
    logger.info('Redirecting to %s', target_url)
    # TODO: frame-busting
    return response


async def platform_or_404(platform_id: str) -> schemas.Platform:
    try:
        return await db.store.platform_async(platform_id)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Platform {platform_id} not found'
        )


def sha256(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    hashed = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.rstrip(b'=').decode('ascii')

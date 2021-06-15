from fastapi import APIRouter, Request

from scale_api import (
    app_config,
    keys,
)

router = APIRouter()


@router.get('/jwks.json')
async def jwks():
    ks = await keys.public_keyset()
    ks_dict = ks.as_dict()
    for entry in ks_dict['keys']:
        if 'use' not in entry:
            entry['use'] = 'sig'
        if 'alg' not in entry:
            entry['alg'] = 'RS256'
    return ks_dict


@router.get('/oauth-authorization-server')
async def oauth_server_metadata(request: Request):
    return {
        'issuer': app_config.JWT_ISSUER,
        'token_endpoint': request.url_for('oauth_token'),
        'response_types_supported': 'token',
        'token_endpoint_auth_methods_supported': [
            'client_secret_basic',
            'private_key_jwt',
        ],
        'jwks_uri': request.url_for('jwks'),
        'grant_types': [
            'client_credentials',
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
        ],
    }

"""
LTI Advantage Services
"""
import logging
import re
import time
import uuid
from collections import namedtuple
from typing import Dict, Sequence

from authlib import jose

from .messages import LtiLaunchRequest
from .. import (
    aio,
    keys,
    schemas,
)

logger = logging.getLogger(__name__)

NEXT_PAGE_REGEX = re.compile(
    r'''^Link:.*<([^>]*)>; ?rel=["']next["']''',
    re.IGNORECASE,
)

CacheItem = namedtuple('TokenCache', 'token expires_at')
ServiceResponse = namedtuple('ServiceResponse', 'headers body next_page')


async def create_platform_token(platform: schemas.Platform) -> str:
    """Returns a JWT used to call LTI Advantage Services.

    LTI Advantage Services such as the Names and Role Provisioning,
    Deep Linking and Assignment and Grade Services use ``client_credentials``
    flow with the ``urn:ietf:params:oauth:client-assertion-type:jwt-bearer``
    assertion type. This function generates the appropriate JWT bearer
    to use for requesting an access token for these services.
    """
    now = time.time()
    payload = {
        'iss': platform.client_id,
        'sub': platform.client_id,
        'aud': str(platform.auth_token_url),
        'iat': now - 5,
        'exp': now + 60,
        'jti': str(uuid.uuid4()),
    }
    private_key = await keys.private_key()
    header = {'typ': 'JWT', 'alg': 'RS256', 'kid': private_key.thumbprint()}
    return jose.jwt.encode(header, payload, private_key).decode('ascii')


class LtiServicesClient:
    """Client for making calls to LTI Advantage Services."""

    def __init__(self, platform: schemas.Platform) -> None:
        self.platform = platform
        self.token_cache: Dict[str, CacheItem] = {}

    async def _access_token(self, scopes: Sequence[str]) -> str:
        """Returns an OAuth access_token."""
        cache_key = ' '.join(sorted(scopes))
        cache_item = self.token_cache.get(cache_key)
        if cache_item and time.time() < (cache_item.expires_at - 10.0):
            return cache_item.token

        jwt = await create_platform_token(self.platform)
        auth_data = {
            'grant_type': 'client_credentials',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': jwt,
            'scope': cache_key,
        }
        auth_url = self.platform.auth_token_url
        headers = {'Accept': 'application/json'}
        r = await aio.http_client.post(auth_url, headers=headers, data=auth_data)
        r.raise_for_status()
        grant_response = r.json()
        access_token = grant_response['access_token']
        expires_in = grant_response['expires_in']

        self.token_cache[cache_key] = CacheItem(
            token=access_token,
            expires_at=time.time() + expires_in,
        )
        return access_token

    async def authorize_header(self, scopes: Sequence[str]) -> Dict[str, str]:
        token = await self._access_token(scopes)
        return {'Authorization': 'Bearer ' + token}

    async def get(
            self,
            scopes: Sequence[str],
            url: str,
            accept: str = 'application/json'
    ) -> ServiceResponse:
        headers = await self.authorize_header(scopes)
        headers['Accept'] = accept
        r = await aio.http_client.get(url, headers=headers)
        r.raise_for_status()
        m = NEXT_PAGE_REGEX.match(r.headers.get('Link', ''))
        next_page = m[1] if m else None
        return ServiceResponse(r.headers, r.json(), next_page)

    async def post(
            self,
            scopes: Sequence[str],
            url: str,
            data: str,
            content_type: str = 'application/json',
            accept: str = 'application/json'
    ) -> ServiceResponse:
        headers = await self.authorize_header(scopes)
        headers['Accept'] = accept
        headers['Content-Type'] = content_type
        r = await aio.http_client.post(url, headers=headers, content=data)
        m = NEXT_PAGE_REGEX.match(r.headers.get('Link', ''))
        next_page = m[1] if m else None
        return ServiceResponse(r.headers, r.json(), next_page)


class NamesRoleService:
    """LTI Advantage Names and Role Provisioning Service client.

    see https://www.imsglobal.org/spec/lti-nrps/v2p0
    """
    SCOPES = ['https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly']
    CONTENT_TYPE = 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json'

    def __init__(self, launch_request: LtiLaunchRequest) -> None:
        self.launch_request = launch_request
        self.client = LtiServicesClient(launch_request.platform)

    async def members(self):
        nrps = self.launch_request.names_role_service
        if not nrps:
            raise Exception('Launch Request does not contan the NRPS Service')
        url = nrps['context_memberships_url']
        result = []
        while url:
            r = await self.client.get(self.SCOPES, url, accept=self.CONTENT_TYPE)
            url = r.next_page
            result += r.body['members']
        return result

"""
LTI Advantage Services
"""
import json
import logging
import re
import time
import uuid
from collections.abc import MutableMapping, Sequence
from typing import Any, NamedTuple, cast

import joserfc.jwt

from .. import aio, keys, schemas
from .messages import LtiLaunchRequest

logger = logging.getLogger(__name__)

NEXT_PAGE_REGEX = re.compile(
    r"""^Link:.*<([^>]*)>; ?rel=["']next["']""",
    re.IGNORECASE | re.MULTILINE,
)


class TokenCacheItem(NamedTuple):
    token: str
    expires_at: float


class ServiceResponse(NamedTuple):
    headers: MutableMapping[str, str]
    body: dict[str, Any]
    next_page: str | None


class LtiServiceError(Exception):
    pass


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
        "iss": platform.client_id,
        "sub": platform.client_id,
        "aud": str(platform.auth_token_url),
        "iat": now - 5,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    private_key = await keys.private_key()
    header = {"typ": "JWT", "alg": "RS256", "kid": private_key.thumbprint()}
    return joserfc.jwt.encode(
        header=header,
        claims=payload,
        key=private_key,
    )


class LtiServicesClient:
    """Client for making calls to LTI Advantage Services."""

    def __init__(self, platform: schemas.Platform) -> None:
        self.platform = platform
        self.token_cache: dict[str, TokenCacheItem] = {}

    async def _access_token(self, scopes: Sequence[str]) -> str:
        """Returns an OAuth access_token."""
        cache_key = " ".join(sorted(scopes))
        cache_item = self.token_cache.get(cache_key)
        if cache_item and time.time() < (cache_item.expires_at - 10.0):
            return cache_item.token

        if self.platform.auth_token_url is None:
            raise ValueError("PLATFORM_NO_TOKEN_URL")

        auth_url = str(self.platform.auth_token_url)
        jwt = await create_platform_token(self.platform)
        auth_data = {
            "grant_type": "client_credentials",
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": jwt,
            "scope": cache_key,
        }
        headers = {"Accept": "application/json"}
        r = await aio.http_client.post(auth_url, headers=headers, data=auth_data)
        grant_response = r.raise_for_status().json()
        access_token = grant_response["access_token"]
        expires_in = grant_response["expires_in"]

        self.token_cache[cache_key] = TokenCacheItem(
            token=access_token,
            expires_at=time.time() + expires_in,
        )
        return cast(str, access_token)

    async def authorize_header(self, scopes: Sequence[str]) -> dict[str, str]:
        token = await self._access_token(scopes)
        return {"Authorization": "Bearer " + token}

    async def get(
        self, scopes: Sequence[str], url: str, accept: str = "application/json"
    ) -> ServiceResponse:
        headers = await self.authorize_header(scopes)
        headers["Accept"] = accept
        r = await aio.http_client.get(url, headers=headers)
        data = r.raise_for_status().json()
        m = NEXT_PAGE_REGEX.match(r.headers.get("Link", ""))
        next_page = m[1] if m else None
        return ServiceResponse(r.headers, data, next_page)

    async def post(
        self,
        scopes: Sequence[str],
        url: str,
        data: str,
        content_type: str = "application/json",
        accept: str = "application/json",
    ) -> ServiceResponse:
        headers = await self.authorize_header(scopes)
        headers["Accept"] = accept
        headers["Content-Type"] = content_type
        r = await aio.http_client.post(url, headers=headers, content=data)
        link_header = r.headers.get("Link")
        if link_header:
            logger.info("Looking for next page link:\n%r", link_header)
            m = NEXT_PAGE_REGEX.search(link_header)
            next_page = m[1] if m else None
        else:
            next_page = None
        return ServiceResponse(r.headers, r.json(), next_page)


class NamesRoleService:
    """LTI Advantage Names and Role Provisioning Service client.

    see https://www.imsglobal.org/spec/lti-nrps/v2p0
    """

    SCOPES = [
        "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
    ]
    CONTENT_TYPE = "application/vnd.ims.lti-nrps.v2.membershipcontainer+json"

    def __init__(self, launch_request: LtiLaunchRequest) -> None:
        self.launch_request = launch_request
        self.client = LtiServicesClient(launch_request.platform)
        if launch_request.names_role_service is None:
            msg = "Launch Request does not contain the NRPS Service"
            logger.warning(msg)
            raise LtiServiceError(msg)
        self.service_url = launch_request.names_role_service["context_memberships_url"]

    async def members(self) -> list[dict[str, Any]]:
        url = self.service_url
        result = []
        while url:
            r = await self.client.get(self.SCOPES, url, accept=self.CONTENT_TYPE)
            url = r.next_page
            result += r.body["members"]
        return result


class AssignmentGradeService:
    """LTI Advantage Assignment and Grade Service client.

    see https://www.imsglobal.org/spec/lti-ags/v2p0
    """

    SCOPES = [
        "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
        "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
        "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
        "https://purl.imsglobal.org/spec/lti-ags/scope/score",
    ]
    CONTENT_TYPE = "application/vnd.ims.lis.v2.lineitem+json"
    CONTENT_TYPE_LIST = "application/vnd.ims.lis.v2.lineitemcontainer+json"
    CONTENT_TYPE_SCORE = "application/vnd.ims.lis.v1.score+json"

    def __init__(self, launch_request: LtiLaunchRequest) -> None:
        self.launch_request = launch_request
        self.client = LtiServicesClient(launch_request.platform)
        if launch_request.assignment_grade_service is None:
            msg = "Launch Request does not contain the AGS Service"
            logger.warning(msg)
            raise LtiServiceError(msg)
        self.lineitems_url = launch_request.assignment_grade_service["lineitems"]
        self.scopes = launch_request.assignment_grade_service["scope"]

    async def lineitems(self) -> list:
        url = self.lineitems_url
        result = []
        while url:
            r = await self.client.get(self.scopes, url, self.CONTENT_TYPE_LIST)
            url = r.next_page
            logger.debug("lineitems r.body: %s", r.body)
        return result

    async def new_lineitem(self) -> None:
        data = {
            "scoreMaximum": 100,
            "label": "Chapter 1 Test",
            "tag": "grade",
        }
        r = await self.client.post(
            self.scopes, self.lineitems_url, json.dumps(data), self.CONTENT_TYPE
        )
        logger.info(r.body)

    async def grade(self) -> None:
        url = "https://fresnostate.instructure.com/api/lti/courses/48069/line_items/9184/scores"
        data = {
            "timestamp": "2023-09-15T21:04:36.736+00:00",
            "scoreGiven": 92,
            "scoreMaximum": 100,
            "activityProgress": "Completed",
            "gradingProgress": "FullyGraded",
            "userId": "74655e36-b83c-451a-a8f3-1883ae0a46bc",
        }
        r = await self.client.post(
            self.scopes, url, json.dumps(data), self.CONTENT_TYPE_SCORE
        )
        logger.info(r)

    def __repr__(self) -> str:
        return f"AssignmentGradeService({self.lineitems_url}, scopes={self.scopes})"

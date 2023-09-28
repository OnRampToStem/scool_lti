"""
LTI Advantage Services
"""
import datetime
import logging
import re
import time
from collections.abc import Sequence
from typing import Annotated, Any, Literal, NamedTuple, TypeAlias, cast

import joserfc.jwt
import shortuuid
from pydantic import BaseModel, Field

from .. import aio, keys, schemas
from .messages import LtiLaunchRequest

logger = logging.getLogger(__name__)

NEXT_PAGE_REGEX = re.compile(
    r"""<([^>]*)>; ?rel=["']next["']""",
    re.IGNORECASE | re.MULTILINE,
)

ActivityProgress: TypeAlias = Literal[
    "Initialized", "Started", "InProgress", "Submitted", "Completed"
]
GradingProgress: TypeAlias = Literal[
    "FullyGraded", "Pending", "PendingManual", "Failed", "NotReady"
]


class LineItem(BaseModel):
    """Assignment and Grade Services Line Item.

    see https://www.imsglobal.org/spec/lti-ags/v2p0#updating-a-line-item
    """

    id: str | None = None
    score_max: Annotated[int, Field(alias="scoreMaximum", gt=0)]
    label: str
    resource_id: Annotated[str | None, Field(alias="resourceId")] = None
    tag: str | None = None
    start_time: Annotated[datetime.datetime | None, Field(alias="startDateTime")] = None
    end_time: Annotated[datetime.datetime | None, Field(alias="endDateTime")] = None
    grades_released: Annotated[bool, Field(alias="gradesReleased")] = True


class Score(BaseModel):
    """Assignment and Grade Services Score.

    see https://www.imsglobal.org/spec/lti-ags/v2p0#score-service-media-type-and-schema
    """

    timestamp: datetime.datetime = datetime.datetime.now(tz=datetime.UTC)
    score_given: Annotated[int, Field(alias="scoreGiven", ge=0)]
    score_max: Annotated[int, Field(alias="scoreMaximum", gt=0)]
    comment: str | None = None
    activity_progress: Annotated[
        ActivityProgress, Field(alias="activityProgress")
    ] = "Completed"
    grading_progress: Annotated[
        GradingProgress, Field(alias="gradingProgress")
    ] = "FullyGraded"
    user_id: Annotated[str, Field(alias="userId")]


class ScaleGrade(BaseModel):
    studentid: str
    courseid: str
    chapter: str
    score: Annotated[int, Field(ge=0)]
    scoremax: Annotated[int, Field(gt=0)]
    timestamp: datetime.datetime = datetime.datetime.now(tz=datetime.UTC)


class TokenCacheItem(NamedTuple):
    token: str
    expires_at: float


class MembersResult(NamedTuple):
    context: dict[str, Any]
    members: list[dict[str, Any]]
    next_page: str | None


class LineItemsResult(NamedTuple):
    items: list[LineItem]
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
        "jti": str(shortuuid.uuid()),
    }
    private_key = await keys.private_key()
    header = {"typ": "JWT", "alg": "RS256", "kid": private_key.thumbprint()}
    return joserfc.jwt.encode(
        header=header,
        claims=payload,
        key=private_key,
    )


def next_page_link(headers: dict[str, Any]) -> str | None:
    if (val := headers.get("Link")) and (m := NEXT_PAGE_REGEX.search(val)):
        return m[1]
    return None


class LtiServicesClient:
    """Client for making calls to LTI Advantage Services."""

    def __init__(self, launch_request: LtiLaunchRequest) -> None:
        self.launch_request = launch_request
        self._token_cache: dict[str, TokenCacheItem] = {}

    async def _access_token(self, scopes: Sequence[str]) -> str:
        """Returns an OAuth access_token."""
        cache_key = " ".join(sorted(scopes))
        cache_item = self._token_cache.get(cache_key)
        if cache_item and time.time() < (cache_item.expires_at - 10.0):
            return cache_item.token

        platform = self.launch_request.platform
        if platform.auth_token_url is None:
            raise ValueError("PLATFORM_NO_TOKEN_URL")

        auth_url = str(platform.auth_token_url)
        jwt = await create_platform_token(platform)
        auth_data = {
            "grant_type": "client_credentials",
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": jwt,
            "scope": cache_key,
        }
        headers = {"Accept": "application/json"}
        logger.info("Retrieving access token from: %s", auth_url)
        r = await aio.http_client.post(auth_url, headers=headers, data=auth_data)
        grant_response = r.raise_for_status().json()
        access_token = grant_response["access_token"]
        expires_in = grant_response["expires_in"]

        self._token_cache[cache_key] = TokenCacheItem(
            token=access_token,
            expires_at=time.time() + expires_in,
        )
        return cast(str, access_token)

    async def authorize_header(self, scopes: Sequence[str]) -> dict[str, str]:
        token = await self._access_token(scopes)
        return {"Authorization": "Bearer " + token}


class NamesRoleService(LtiServicesClient):
    """LTI Advantage Names and Role Provisioning Service client.

    see https://www.imsglobal.org/spec/lti-nrps/v2p0
    """

    SCOPES = [
        "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
    ]

    @property
    def service_url(self) -> str:
        if self.launch_request.names_role_service is None:
            msg = "Launch Request does not contain the NRPS Service"
            logger.warning(msg)
            raise LtiServiceError(msg)
        return cast(
            str, self.launch_request.names_role_service["context_memberships_url"]
        )

    async def members(self, next_page_url: str | None = None) -> MembersResult:
        headers = await self.authorize_header(self.SCOPES)
        headers["Accept"] = "application/vnd.ims.lti-nrps.v2.membershipcontainer+json"
        url = next_page_url if next_page_url is not None else self.service_url
        r = await aio.http_client.get(url=url, headers=headers)
        data = r.raise_for_status().json()
        return MembersResult(
            context=data["context"],
            members=data["members"],
            next_page=next_page_link(r.headers),  # type: ignore[arg-type]
        )


class AssignmentGradeService(LtiServicesClient):
    """LTI Advantage Assignment and Grade Service client.

    see https://www.imsglobal.org/spec/lti-ags/v2p0
    """

    CONTENT_TYPE = "application/vnd.ims.lis.v2.lineitem+json"
    CONTENT_TYPE_LIST = "application/vnd.ims.lis.v2.lineitemcontainer+json"
    CONTENT_TYPE_SCORE = "application/vnd.ims.lis.v1.score+json"

    @property
    def service_url(self) -> str:
        if self.launch_request.assignment_grade_service is None:
            msg = "Launch Request does not contain the AGS Service"
            logger.warning(msg)
            raise LtiServiceError(msg)
        if service_url := self.launch_request.assignment_grade_service.get("lineitems"):
            return cast(str, service_url)
        msg = "Launch Request does not contain the lineitems URL"
        logger.warning(msg)
        raise LtiServiceError(msg)

    @property
    def scopes(self) -> Sequence[str]:
        return self.launch_request.assignment_grade_service["scope"]  # type: ignore

    async def lineitems(self, next_page_url: str | None = None) -> LineItemsResult:
        """Returns the list of assignments for this launch request context."""
        url = next_page_url if next_page_url is not None else self.service_url
        headers = await self.authorize_header(self.scopes)
        headers["Accept"] = self.CONTENT_TYPE_LIST
        r = await aio.http_client.get(url=url, headers=headers)
        items = [LineItem.model_validate(item) for item in r.raise_for_status().json()]
        return LineItemsResult(
            items=items,
            next_page=next_page_link(r.headers),  # type: ignore[arg-type]
        )

    async def lineitem(self, label: str) -> LineItem | None:
        next_page = None
        while True:
            result = await self.lineitems(next_page_url=next_page)
            for item in result.items:
                if item.label == label:
                    return item
            if next_page := result.next_page:
                continue
            return None

    async def add_lineitem(self, item: LineItem) -> LineItem:
        """Adds a new assignment for this launch request context."""
        headers = await self.authorize_header(self.scopes)
        headers["Accept"] = self.CONTENT_TYPE
        headers["Content-Type"] = self.CONTENT_TYPE
        content = item.model_dump_json(
            exclude={"id"}, by_alias=True, exclude_unset=True
        )
        r = await aio.http_client.post(
            url=self.service_url, headers=headers, content=content
        )
        return LineItem.model_validate(r.raise_for_status().json())

    async def add_score(self, item: LineItem, score: Score) -> None:
        """Adds a score to an existing assignment."""
        if item.id is None:
            msg = f"LineItem does not have an ID attribute: {item!r}"
            logger.warning(msg)
            raise LtiServiceError(msg)
        score_url = f"{item.id.rstrip('/')}/scores"
        headers = await self.authorize_header(self.scopes)
        headers["Accept"] = self.CONTENT_TYPE_SCORE
        headers["Content-Type"] = self.CONTENT_TYPE_SCORE
        content = score.model_dump_json(by_alias=True, exclude_none=True)
        try:
            rv = await aio.http_client.post(
                url=score_url, headers=headers, content=content
            )
        except Exception:
            logger.exception("call to [%s] with [%s] failed", score_url, content)
            raise
        else:
            logger.debug("add_score status=%s - %s", rv.status_code, rv.text)

    def __repr__(self) -> str:
        return f"AssignmentGradeService({self.service_url}, scopes={self.scopes})"

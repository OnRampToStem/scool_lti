"""
SCALE Application schemas
"""
import datetime
import json
import logging
from collections.abc import Mapping
from typing import Annotated, Any, Literal, NamedTuple, Self, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    EmailStr,
    Field,
    HttpUrl,
    SecretStr,
    field_validator,
)

logger = logging.getLogger(__name__)


def make_secret(val: str) -> SecretStr:
    return SecretStr(val)


def _normalize_lti_role(v: str) -> str:
    if v.startswith("http://purl.imsglobal.org/vocab/lis/v2/membership#"):
        return v.rsplit("#")[1]
    return v


LTIRole = Annotated[str, AfterValidator(_normalize_lti_role)]

ActivityProgress: TypeAlias = Literal[
    "Initialized", "Started", "InProgress", "Submitted", "Completed"
]

GradingProgress: TypeAlias = Literal[
    "FullyGraded", "Pending", "PendingManual", "Failed", "NotReady"
]


class DBBaseModel(BaseModel):
    model_config = {"from_attributes": True}


class Platform(DBBaseModel):
    """Learning Management System (LMS) Platform.

    A standalone schema class for ``scale_api.db.Platform``.
    """

    id: str
    name: str
    issuer: str | None = None
    oidc_auth_url: HttpUrl | None = None
    auth_token_url: HttpUrl | None = None
    jwks_url: HttpUrl | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None


class AuthUser(DBBaseModel):
    """Authorized User.

    A standalone schema class for ``scale_api.db.AuthUser``.
    """

    id: str
    client_id: str
    client_secret_hash: str
    is_active: bool = True
    scopes: list[str] | None = None
    context: Mapping[str, str] | None = None

    @field_validator("scopes", mode="before")
    def assemble_scopes(cls, v: str | (list[str] | None)) -> list[str]:
        """Converts a space separated scope string to a list."""
        if v is None:
            return []
        if isinstance(v, str):
            return v.split()
        if isinstance(v, list):
            return v
        raise ValueError(v)

    @property
    def is_superuser(self) -> bool:
        """Returns True if the ``superuser`` scope is present."""
        if self.scopes:
            return "role:superuser" in self.scopes
        return False

    @classmethod
    def from_scale_user(cls, scale_user: "ScaleUser") -> Self:
        """Converts an ``ScaleUser`` to a ``AuthUser``."""
        return cls(
            id=scale_user.id or scale_user.email,
            client_id=scale_user.email,
            client_secret_hash="none",  # noqa: S106
            scopes=["role:" + r for r in scale_user.roles],
            context=scale_user.context,
        )

    def session_dict(self) -> dict[str, Any]:
        """Returns a dict object suitable for storing in a web session."""
        return self.model_dump(exclude_defaults=True)


class ScaleUser(BaseModel):
    """SCALE User.

    This represents a user authenticated via LTI from an LMS such as
    Canvas.
    """

    id: str | None = None
    email: EmailStr
    name: str | None = None
    picture: str | None = None

    # Roles provided by LTI. There are different types of roles such as
    # those the user has in the system overall and those assigned for the
    # Course (Context). For our purposes, we only include here those roles
    # assigned for the Context.
    #
    # see https://www.imsglobal.org/spec/lti/v1p3#context-claim
    roles: list[LTIRole] = []

    # Context is the term used by LTI to represent a Course in the LMS.
    # We keep the same terminology in our schema. Context provides both
    # a Course ID and Title.
    context: Mapping[str, str] | None = None

    def session_dict(self) -> dict[str, Any]:
        """Returns a dict object suitable for storing in a web session."""
        return self.model_dump(exclude_defaults=True)

    @property
    def user_id(self) -> str:
        """Returns the Platform uuid for this user."""
        if self.id is not None:
            user_id, sep, other = self.id.rpartition("@")
            return user_id if sep else other
        raise ValueError("USER_ID", repr(self))

    @property
    def platform_id(self) -> str:
        """Returns the Platform ID for this user."""
        if self.id:
            user_id, sep, plat_id = self.id.rpartition("@")
            if sep:
                return plat_id
        return "scale_api"

    @property
    def context_id(self) -> str:
        """Returns the LMS Context (Course) ID for this user."""
        return self.context["id"] if self.context else "scale_api"

    @property
    def is_instructor(self) -> bool:
        """Returns True if this request contains an instructor role."""
        lower_roles = {r.lower() for r in self.roles}
        if {"instructor", "teacher"} & lower_roles:
            return True
        return False

    @property
    def is_student(self) -> bool:
        """Returns True if this request contains the learner role."""
        lower_roles = {r.lower() for r in self.roles}
        if {"learner", "student"} & lower_roles:
            return True
        return False

    @classmethod
    def from_auth_user(cls, auth_user: AuthUser) -> Self:
        """Converts an ``AuthUser`` to a ``ScaleUser``."""
        if auth_user.scopes:
            roles = [
                r.split(":", 1)[1] for r in auth_user.scopes if r.startswith("role:")
            ]
        else:
            roles = []
        return cls(
            id=auth_user.id,
            email=auth_user.client_id,
            name=None,
            picture=None,
            roles=roles,
            context=auth_user.context,
        )


class AuthJsonWebKey(DBBaseModel):
    """JSON Web Key.

    A standalone schema class for ``scale_api.db.AuthJsonWebKey``.
    """

    kid: str
    data: SecretStr
    valid_from: datetime.datetime
    valid_to: datetime.datetime | None = None

    @field_validator("valid_from", "valid_to", mode="before")
    def tz_aware_dates(cls, v: datetime.datetime | None) -> datetime.datetime | None:
        if v is None:
            return None
        if v.tzinfo is not None and v.tzinfo.utcoffset(None) is not None:
            return v
        return v.replace(tzinfo=datetime.UTC)

    @property
    def is_valid(self) -> bool:
        now = datetime.datetime.now(tz=datetime.UTC)
        if self.valid_from > now:
            return False
        return self.valid_to is None or self.valid_to > now


class LtiServiceError(Exception):
    def __init__(self, message: str | None = None, status_code: int = 500) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(f"{status_code}: {message}")


class LtiLaunchRequest:
    """LTI Launch Request.

    Provides information based on either a ResourceLink or DeepLink request
    message received from an LTI 1.3 IDToken.
    """

    def __init__(self, platform: Platform, message: str | dict[str, Any]) -> None:
        data = json.loads(message) if isinstance(message, str) else message
        version = data["https://purl.imsglobal.org/spec/lti/claim/version"]
        if version != "1.3.0":
            raise ValueError("INVALID_MESSAGE_VERSION", version)
        self.message = data
        self.platform = platform

    @property
    def sub(self) -> str:
        return self.message["sub"]  # type: ignore[no-any-return]

    @property
    def launch_id(self) -> str:
        """Returns an id for this request that is associated with a given user."""
        return self.launch_id_for(self.scale_user)

    @staticmethod
    def launch_id_for(scale_user: ScaleUser) -> str:
        """Returns an id for a given user.

        This method is meant to be used to retrieve a cached
        ``LtiLaunchRequest`` for the given user.
        """
        return f"lti-launch-request-{scale_user.id}@{scale_user.context_id}"

    @property
    def roles(self) -> list[str]:
        """Returns a list of roles for this context."""
        return [
            r.rsplit("#")[1]
            for r in self.message["https://purl.imsglobal.org/spec/lti/claim/roles"]
            if r.startswith("http://purl.imsglobal.org/vocab/lis/v2/membership#")
        ]

    @property
    def context(self) -> dict[str, str]:
        """Returns the Course information from the request."""
        return {
            k: v
            for k, v in self.message[
                "https://purl.imsglobal.org/spec/lti/claim/context"
            ].items()
            if k in ("id", "title")
        }

    @property
    def message_type(self) -> str:
        """Returns the message type, could be either a resource or deep link type."""
        return self.message[  # type: ignore[no-any-return]
            "https://purl.imsglobal.org/spec/lti/claim/message_type"
        ]

    @property
    def is_resource_link_launch(self) -> bool:
        """Returns True if this is a ResourceLink request."""
        return self.message_type == "LtiResourceLinkRequest"

    @property
    def is_deep_link_launch(self) -> bool:
        """Returns True if this is a DeepLinking request."""
        return self.message_type == "LtiDeepLinkingRequest"

    @property
    def is_instructor(self) -> bool:
        """Returns True if this request contains an instructor role."""
        lower_roles = {r.lower() for r in self.roles}
        if {"instructor", "teacher"} & lower_roles:
            return True
        return False

    @property
    def is_student(self) -> bool:
        """Returns True if this request contains the learner role."""
        lower_roles = {r.lower() for r in self.roles}
        if {"learner", "student"} & lower_roles:
            return True
        return False

    @property
    def names_role_service(self) -> dict[str, Any] | None:
        return self.message.get(  # type: ignore[no-any-return]
            "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice"
        )

    @property
    def assignment_grade_service(self) -> dict[str, Any] | None:
        return self.message.get(  # type: ignore[no-any-return]
            "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
        )

    @property
    def scale_user(self) -> ScaleUser:
        """Returns a ``ScaleUser`` based on data from the request."""
        lms_userid = self.message["sub"] + "@" + self.platform.id
        lms_email = self.message.get("email") or self._custom_field("email")
        lms_name = self.message.get("name") or self._custom_field("name")
        lms_picture = self.message.get("picture") or self._custom_field("picture")
        if not lms_email:
            # Special handling for using the "Student View" feature in Canvas
            if (
                lms_name == "Test Student"
                and self.message["iss"] == "https://canvas.instructure.com"
            ):
                lms_email = "test_student@canvas.instructure.com"
            else:
                raise ValueError("MISSING_REQUIRED_ATTRIBUTE", "email")

        return ScaleUser(
            id=lms_userid,
            email=lms_email,
            name=lms_name,
            picture=lms_picture,
            roles=self.roles,
            context=self.context,
        )

    def _custom_field(self, field_name: str) -> str | None:
        """Returns the value of the given custom field name, if present.

        See the Troubleshooting section of `docs/lti/canvas_install.md` for
        details on how to add the custom fields.
        """
        logger.debug("Looking for custom field [%s]", field_name)
        return self.message.get(  # type: ignore[no-any-return]
            "https://purl.imsglobal.org/spec/lti/claim/custom", {}
        ).get(field_name)

    def dumps(self) -> str:
        """Serializes the request to a string suitable for storing."""
        p = self.platform.model_dump_json(exclude={"client_secret"})
        m = json.dumps(self.message)
        return f'{{"platform":{p},"message":{m}}}'

    @staticmethod
    def loads(data: str) -> "LtiLaunchRequest":
        """Returns a ``LtiLaunchRequest`` from a json string."""
        content = json.loads(data)
        platform = Platform.model_validate(content["platform"])
        return LtiLaunchRequest(platform, content["message"])

    def __str__(self) -> str:
        return f"LtiLaunchRequest({self.platform.id}, {self.message_type})"


class LineItem(BaseModel):
    """Assignment and Grade Services Line Item.

    see https://www.imsglobal.org/spec/lti-ags/v2p0#updating-a-line-item
    """

    id: str | None = None
    score_max: Annotated[int | float, Field(alias="scoreMaximum", gt=0)]
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
    score_given: Annotated[int | float, Field(alias="scoreGiven", ge=0)]
    score_max: Annotated[int | float, Field(alias="scoreMaximum", gt=0)]
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
    score: Annotated[int | float, Field(ge=0)]
    scoremax: Annotated[int | float, Field(gt=0)]
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

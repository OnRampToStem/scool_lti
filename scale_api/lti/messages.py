"""
LTI Messages

This module defines classes that help to model and consume LTI messages
such as Resource Link and Deep Link request and response messages.
"""
import json
import logging
from collections.abc import Mapping
from typing import Any

from .. import schemas

MESSAGE_TYPE_KEY = "https://purl.imsglobal.org/spec/lti/claim/message_type"
MESSAGE_VERSION_KEY = "https://purl.imsglobal.org/spec/lti/claim/version"
MESSAGE_CONTEXT_KEY = "https://purl.imsglobal.org/spec/lti/claim/context"
MESSAGE_ROLES_KEY = "https://purl.imsglobal.org/spec/lti/claim/roles"
MESSAGE_TOOL_KEY = "https://purl.imsglobal.org/spec/lti/claim/tool_platform"
MESSAGE_CUSTOM_KEY = "https://purl.imsglobal.org/spec/lti/claim/custom"

logger = logging.getLogger(__name__)


class LtiLaunchRequest:
    """LTI Launch Request.

    Provides information based on either a ResourceLink or DeepLink request
    message received from an LTI 1.3 IDToken.
    """

    def __init__(
        self, platform: schemas.Platform, message: str | Mapping[str, Any]
    ) -> None:
        message_obj = json.loads(message) if isinstance(message, str) else message
        if message_obj[MESSAGE_VERSION_KEY] != "1.3.0":
            raise ValueError(
                "INVALID_MESSAGE_VERSION", message_obj[MESSAGE_VERSION_KEY]
            )
        self.message = message_obj
        self.platform = platform

    @property
    def sub(self) -> str:
        return self.message["sub"]  # type: ignore[no-any-return]

    @property
    def launch_id(self) -> str:
        """Returns an id for this request that is associated with a given user."""
        return self.launch_id_for(self.scale_user)

    @staticmethod
    def launch_id_for(scale_user: schemas.ScaleUser) -> str:
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
            for r in self.message[MESSAGE_ROLES_KEY]
            if r.startswith("http://purl.imsglobal.org/vocab/lis/v2/membership#")
        ]

    @property
    def context(self) -> Mapping[str, str]:
        """Returns the Course information from the request."""
        return {
            k: v
            for k, v in self.message[MESSAGE_CONTEXT_KEY].items()
            if k in ("id", "title")
        }

    @property
    def message_type(self) -> str:
        """Returns the message type, could be either a resource or deep link type."""
        return self.message[MESSAGE_TYPE_KEY]  # type: ignore[no-any-return]

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
    def scale_user(self) -> schemas.ScaleUser:
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
        # noinspection PyTypeChecker
        return schemas.ScaleUser(
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
        logger.warning("Looking for custom field [%s]", field_name)
        return self.message.get(  # type: ignore[no-any-return]
            MESSAGE_CUSTOM_KEY, {}
        ).get(field_name)

    def dumps(self) -> str:
        """Serializes the request to a string suitable for storing."""
        p = self.platform.model_dump_json(exclude={"client_secret"})
        m = json.dumps(self.message)
        return "{" f'"platform":{p},"message":{m}' "}"  # noqa: ISC001

    @staticmethod
    def loads(data: str) -> "LtiLaunchRequest":
        """Returns a ``LtiLaunchRequest`` from a json string."""
        content = json.loads(data)
        platform = schemas.Platform.model_validate(content["platform"])
        return LtiLaunchRequest(platform, content["message"])

    def __str__(self) -> str:
        return f"LtiLaunchRequest({self.platform.id}, {self.message_type})"

"""
LTI Messages

This module defines classes that help to model and consume LTI messages
such as Resource Link and Deep Link request and response messages.
"""
import json
from typing import Any, List, Mapping, Union

from .. import schemas

MESSAGE_TYPE_KEY = 'https://purl.imsglobal.org/spec/lti/claim/message_type'
MESSAGE_VERSION_KEY = 'https://purl.imsglobal.org/spec/lti/claim/version'
MESSAGE_CONTEXT_KEY = 'https://purl.imsglobal.org/spec/lti/claim/context'
MESSAGE_ROLES_KEY = 'https://purl.imsglobal.org/spec/lti/claim/roles'
MESSAGE_TOOL_KEY = 'https://purl.imsglobal.org/spec/lti/claim/tool_platform'
MESSAGE_CUSTOM_KEY = 'https://purl.imsglobal.org/spec/lti/claim/custom'


class LtiLaunchRequest:
    """LTI Launch Request.

    Provides information based on either a ResourceLink or DeepLink request
    message received from an LTI 1.3 IDToken.
    """
    def __init__(
            self,
            platform: schemas.Platform,
            message: Union[str, Mapping[str, Any]]
    ) -> None:
        if isinstance(message, str):
            message = json.loads(message)
        if message[MESSAGE_VERSION_KEY] != '1.3.0':
            raise ValueError(
                f'Invalid message version: {message[MESSAGE_VERSION_KEY]}'
            )
        self.message = message
        self.platform = platform

    @property
    def launch_id(self) -> str:
        """Returns an id for this request that is associated with a given user."""
        return f'lti-launch-request-{self.scale_user.id}'

    @staticmethod
    def launch_id_for(scale_user: schemas.ScaleUser) -> str:
        """Returns an id for a given user.

        This method is meant to be used to retrieve a cached
        ``LtiLaunchRequest`` for the given user.
        """
        return f'lti-launch-request-{scale_user.id}'

    @property
    def roles(self) -> List[str]:
        """Returns a list of roles for this context."""
        return [
            r.rsplit('#')[1]
            for r in self.message[MESSAGE_ROLES_KEY]
            if r.startswith('http://purl.imsglobal.org/vocab/lis/v2/membership#')
        ]

    @property
    def context(self) -> Mapping[str, str]:
        """Returns the Course information from the request."""
        return {
            k: v for k, v in self.message[MESSAGE_CONTEXT_KEY].items()
            if k in ('id', 'title')
        }

    @property
    def message_type(self) -> str:
        """Returns the message type, could be either a resource or deep link type."""
        return self.message[MESSAGE_TYPE_KEY]

    @property
    def is_resource_link_launch(self) -> bool:
        """Returns True if this is a ResourceLink request."""
        return self.message_type == 'LtiResourceLinkRequest'

    @property
    def is_deep_link_launch(self) -> bool:
        """Returns True if this is a DeepLinking request."""
        return self.message_type == 'LtiDeepLinkingRequest'

    @property
    def is_instructor(self) -> bool:
        """Returns True if this request contains an instructor role."""
        lower_roles = {r.lower() for r in self.roles}
        if {'instructor', 'teacher'} & lower_roles:
            return True
        return False

    @property
    def is_student(self) -> bool:
        """Returns True if this request contains the learner role."""
        lower_roles = {r.lower() for r in self.roles}
        if {'learner', 'student'} & lower_roles:
            return True
        return False

    @property
    def scale_user(self) -> schemas.ScaleUser:
        """Returns a ``ScaleUser`` based on data from the request."""
        tool_platform = self.message[MESSAGE_TOOL_KEY]
        user_id = self.message['sub'] + '@' + tool_platform['guid']
        email = self.message.get('email')
        if not email:
            if 'fresno' in tool_platform['name'].lower():
                login_id = self.message[MESSAGE_CUSTOM_KEY]['canvas_user_login_id']
                email = login_id.lower()
                if '@' not in email:
                    email += '@mail.fresnostate.edu'
        return schemas.ScaleUser(
            id=user_id,
            email=email,
            roles=self.roles,
            context=self.context,
        )

    def dumps(self) -> str:
        """Serializes the request to a string suitable for storing."""
        data = {
            'platform': self.platform.dict(exclude={'client_secret'}),
            'message': self.message,
        }
        return json.dumps(data)

    @staticmethod
    def loads(self, data: str) -> 'LtiLaunchRequest':
        """Returns a ``LtiLaunchRequest`` from a json string."""
        content = json.loads(data)
        platform = schemas.Platform.parse_obj(content['platform'])
        return LtiLaunchRequest(platform, content['message'])

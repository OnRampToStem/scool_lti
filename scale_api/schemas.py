"""
SCALE Application schemas
"""
import datetime
from collections.abc import Mapping
from typing import Optional, Union

from pydantic import (
    BaseModel,
    EmailStr,
    HttpUrl,
    SecretStr,
    validator,
)


class Platform(BaseModel):
    """Learning Management System (LMS) Platform.

    A standalone schema class for ``scale_api.db.Platform``.
    """
    id: str
    name: str
    issuer: str
    oidc_auth_url: HttpUrl
    auth_token_url: Optional[HttpUrl]
    jwks_url: HttpUrl
    client_id: Optional[str]
    client_secret: Optional[SecretStr]

    class Config:
        orm_mode = True


class AuthUser(BaseModel):
    """Authorized User.

    A standalone schema class for ``scale_api.db.AuthUser``.
    """
    id: str
    client_id: str
    client_secret_hash: str
    is_active: bool = True
    is_verified: bool = False
    scopes: Optional[list[str]]
    context: Optional[Mapping[str, str]]

    @validator('scopes', pre=True)
    def assemble_scopes(cls, v: Union[str, list[str]]) -> list[str]:
        """Converts a space separated scope string to a list."""
        if v is None:
            return []
        if isinstance(v, str):
            return v.split()
        elif isinstance(v, list):
            return v
        raise ValueError(v)

    @property
    def is_superuser(self) -> bool:
        """Returns True if the ``superuser`` scope is present."""
        if self.scopes:
            return 'role:superuser' in self.scopes
        return False

    @classmethod
    def from_scale_user(cls, scale_user: 'ScaleUser') -> 'AuthUser':
        """Converts an ``ScaleUser`` to a ``AuthUser``."""
        roles = ['role:' + r for r in scale_user.roles]
        return cls(
            id=scale_user.id,
            client_id=scale_user.email,
            client_secret_hash='none',
            scopes=roles,
            context=scale_user.context,
        )

    def session_dict(self):
        """Returns a dict object suitable for storing in a web session."""
        return self.dict(exclude_defaults=True)

    class Config:
        orm_mode = True


class ScaleUser(BaseModel):
    """SCALE User.

    This represents a user authenticated via LTI from an LMS such as
    Canvas.
    """
    id: Optional[str]
    email: EmailStr
    name: Optional[str]
    picture: Optional[str]

    # Roles provided by LTI. There are different types of roles such as
    # those the user has in the system overall and those assigned for the
    # Course (Context). For our purposes, we only include here those roles
    # assigned for the Context.
    #
    # see https://www.imsglobal.org/spec/lti/v1p3#context-claim
    roles: list[str] = []

    # Context is the term used by LTI to represent a Course in the LMS.
    # We keep the same terminology in our schema. Context provides both
    # a Course ID and Title.
    context: Optional[Mapping[str, str]]

    def session_dict(self):
        """Returns a dict object suitable for storing in a web session."""
        return self.dict(exclude_defaults=True)

    @property
    def user_id(self) -> str:
        """Returns the Platform uuid for this user."""
        if self.id is not None:
            user_id, sep, other = self.id.rpartition('@')
            return user_id if sep else other
        raise ValueError(f'Unable to determine UUID for this user: {self!r}')

    @property
    def platform_id(self) -> str:
        """Returns the Platform ID for this user."""
        if self.id:
            user_id, sep, plat_id = self.id.rpartition('@')
            if sep:
                return plat_id
        return 'scale_api'

    @property
    def context_id(self) -> str:
        """Returns the LMS Context (Course) ID for this user."""
        return self.context['id'] if self.context else 'scale_api'

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

    @classmethod
    def from_auth_user(cls, auth_user: AuthUser) -> 'ScaleUser':
        """Converts an ``AuthUser`` to a ``ScaleUser``."""
        if auth_user.scopes:
            roles = [
                r.split(':', 1)[1]
                for r in auth_user.scopes
                if r.startswith('role:')
            ]
        else:
            roles = []
        return cls(
            id=auth_user.id,
            email=auth_user.client_id,  # type:ignore
            roles=roles,
            context=auth_user.context,
        )

    @validator('roles', each_item=True)
    def normalize_roles(cls, v: str) -> str:
        if v.startswith('http://purl.imsglobal.org/vocab/lis/v2/membership#'):
            return v.rsplit('#')[1]
        return v


class ScaleUserImpersonationRequest(ScaleUser):
    """Specialized ScaleUser run-as request.

    This is used to allow local developers to impersonate a ScaleUser.
    This should only be used in non-production environments and is meant to
    allow devs to provide the ``scale_api.app_config.SECRET_KEY`` and provide
    custom ``ScaleUser`` values for testing purposes.
    """
    secret_key: SecretStr

    def session_dict(self):
        """Returns a dict object suitable for storing in a web session."""
        return self.dict(exclude={'secret_key'}, exclude_defaults=True)


class AuthJsonWebKey(BaseModel):
    """JSON Web Key.

    A standalone schema class for ``scale_api.db.AuthJsonWebKey``.
    """
    kid: str
    data: SecretStr
    valid_from: datetime.datetime
    valid_to: Optional[datetime.datetime]

    @property
    def is_valid(self) -> bool:
        now = datetime.datetime.utcnow()
        if self.valid_from > now:
            return False
        return self.valid_to is None or self.valid_to > now

    class Config:
        orm_mode = True


class Message(BaseModel):
    """Messages.

    A standalone schema class for ``scale_api.db.Message``.
    """
    id: str
    subject: str
    header: Optional[str]
    body: Optional[str]
    status: str = 'active'
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        orm_mode = True


class BinaryFile(BaseModel):
    """Binary File.

    A standalone schema class for ``scale_api.db.BinData``.
    """
    id: str
    content_type: str = 'application/octet-stream'
    name: Optional[str]
    status: str = 'active'
    created_at: datetime.datetime
    updated_at: datetime.datetime
    data: bytes

    class Config:
        orm_mode = True

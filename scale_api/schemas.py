"""
SCALE Application schemas
"""
import datetime
from typing import List, Mapping, Optional, Union

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
    scopes: Optional[List[str]]

    @validator('scopes', pre=True)
    def assemble_scopes(cls, v: Union[str, List[str]]) -> List[str]:
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
        """Returns True if the the ``superuser`` scope is present."""
        return self.scopes and 'role:superuser' in self.scopes

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
    id: str = '1'
    email: EmailStr

    # Roles provided by LTI. There are different types of roles such as
    # those the user has in the system overall and those assigned for the
    # Course (Context). For our purposes, we only include here those roles
    # assigned for the Context.
    #
    # see https://www.imsglobal.org/spec/lti/v1p3#context-claim
    roles: List[str] = []

    # Context is the term used by LTI to represent a Course in the LMS.
    # We keep the same terminology in our schema. Context provides both
    # a Course ID and Title.
    context: Optional[Mapping[str, str]]

    def session_dict(self):
        """Returns a dict object suitable for storing in a web session."""
        return self.dict(exclude_defaults=True)

    @classmethod
    def from_auth_user(cls, auth_user: AuthUser) -> 'ScaleUser':
        """Converts an ``AuthUser`` to a ``ScaleUser``."""
        roles = [
            r.split(':', 1)[1]
            for r in auth_user.scopes
            if r.startswith('role:')
        ]
        return cls(id=auth_user.id, email=auth_user.client_id, roles=roles)


class ScaleUserImpersonationRequest(ScaleUser):
    """Specialized ScaleUser run-as request.

    This is used to allow local developers to impersonate a ScaleUser.
    This should only be used in non-production environments and is meant to
    allow devs to provide the ``scale_api.app_config.SECRET_KEY`` and provide
    custom ``ScaleUser`` values for testing purposes.
    """
    secret_key: SecretStr


class AuthJsonWebKey(BaseModel):
    """JSON Web Key.

    A standalone schema class for ``scale_api.db.AuthJsonWebKey``.
    """
    kid: str
    data: SecretStr
    valid_from: datetime.datetime
    valid_to: Optional[datetime.datetime]

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

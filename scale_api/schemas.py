import enum
import datetime
from typing import Any, List, Mapping, Optional, Union

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    HttpUrl,
    SecretStr,
    validator,
)


class EntryStatus(enum.IntEnum):
    active = 1
    inactive = 0
    deleted = -1


class Platform(BaseModel):
    id: str
    name: str
    issuer: str
    oidc_auth_url: HttpUrl
    auth_token_url: Optional[HttpUrl]
    jwks_url: HttpUrl
    client_id: Optional[str]
    client_secret: Optional[SecretStr]

    # TODO: track deployments??
    # deployments: List[str]

    class Config:
        orm_mode = True


class AuthUser(BaseModel):
    id: str
    client_id: str
    client_secret_hash: str
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    scopes: Optional[List[str]]

    @validator('scopes', pre=True)
    def assemble_scopes(cls, v: Union[str, List[str]]) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return v.split()
        elif isinstance(v, list):
            return v
        raise ValueError(v)

    def session_dict(self):
        return self.dict(exclude_defaults=True)

    class Config:
        orm_mode = True


class ScaleUser(BaseModel):
    email: EmailStr
    roles: List[str] = []


class ScaleUserImpersonationRequest(ScaleUser):
    secret_key: SecretStr


class AuthJsonWebKey(BaseModel):
    kid: str
    data: SecretStr
    valid_from: datetime.datetime
    valid_to: Optional[datetime.datetime]

    class Config:
        orm_mode = True


class Message(BaseModel):
    id: str
    subject: str
    header: Optional[str]
    body: Optional[str]
    status: EntryStatus
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        orm_mode = True


class LtiUser(BaseModel):
    roles: List[str] = Field(..., alias='https://purl.imsglobal.org/spec/lti/claim/roles')
    email: Optional[EmailStr]

    # TODO: populate from an SIS
    majors: List[str] = []
    pronouns: List[str] = []
    grade_level: Optional[str]

    @validator('roles', each_item=True)
    def parse_roles(cls, v: str) -> str:
        _, sep, role = v.rpartition('/')
        return role.lower()

    @classmethod
    def from_id_token(cls, id_token: Mapping[str, Any]) -> 'LtiUser':
        return cls.parse_obj(id_token)


class LtiResourceLink(BaseModel):
    __namespace__ = 'https://purl.imsglobal.org/spec/lti/claim/resource_link'

    id: str
    title: Optional[str]
    description: Optional[str]

    @classmethod
    def from_id_token(cls, id_token: Mapping[str, Any]) -> 'LtiResourceLink':
        content = id_token[cls.__namespace__]
        return cls.parse_obj(content)


class LtiContext(BaseModel):
    __namespace__ = 'https://purl.imsglobal.org/spec/lti/claim/context'

    id: str
    label: str
    title: str
    type: List[str]
    deployment_id: Optional[str]

    user: LtiUser
    resource_link: LtiResourceLink

    @classmethod
    def from_id_token(cls, id_token: Mapping[str, Any]) -> 'LtiContext':
        user = LtiUser.from_id_token(id_token)
        resource_link = LtiResourceLink.from_id_token(id_token)
        context = id_token[cls.__namespace__]
        context['deployment_id'] = id_token.get('https://purl.imsglobal.org/spec/lti/claim/deployment_id')
        return cls(**context, user=user, resource_link=resource_link)

import datetime
from typing import List, Optional, Union

from pydantic import (
    BaseModel,
    EmailStr,
    HttpUrl,
    SecretStr,
    validator,
)


class Platform(BaseModel):
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
    id: str
    client_id: str
    client_secret_hash: str
    is_active: bool = True
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

    @property
    def is_superuser(self) -> bool:
        return self.scopes and 'role:superuser' in self.scopes

    def session_dict(self):
        return self.dict(exclude_defaults=True)

    class Config:
        orm_mode = True


class ScaleUser(BaseModel):
    id: str = '1'
    email: EmailStr
    roles: List[str] = []

    def session_dict(self):
        return self.dict(exclude_defaults=True)

    @classmethod
    def from_auth_user(cls, auth_user: AuthUser) -> 'ScaleUser':
        roles = [
            r.split(':', 1)[1]
            for r in auth_user.scopes
            if r.lower() in (
                'role:instructor',
                'role:student',
                'role:teacher',
                'role:learner',
            )
        ]
        return cls(id=auth_user.id, email=auth_user.client_id, roles=roles)


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
    status: str = 'active'
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        orm_mode = True

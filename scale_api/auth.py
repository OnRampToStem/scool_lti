import base64
import datetime
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union

import authlib.jose.errors
from authlib import jose
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import (
    OAuth2,
    SecurityScopes,
)
from fastapi.security.utils import get_authorization_scheme_param
from passlib.context import CryptContext

from scale_api import (
    app_config,
    schemas,
)

logger = logging.getLogger(__name__)

JWT_KEY = app_config.SECRET_KEY
JWT_ALGORITHM = app_config.JWT_ALGORITHM
JWT_ISSUER = app_config.JWT_ISSUER

AUTH_USER_TOKEN_OPTS = {
    'iss': {'essential': True, 'value': app_config.JWT_ISSUER},
    'aud': {'essential': True, 'value': app_config.JWT_ISSUER},
    'sub': {'essential': True},
    'unique_name': {'essential': True}
}

JWT = jose.JsonWebToken([app_config.JWT_ALGORITHM])

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


@dataclass
class ProofKey:
    def __init__(self, verifier: str = None) -> None:
        if verifier is None:
            verifier = secrets.token_urlsafe(64)
        self.verifier = verifier

    @property
    def challenge(self) -> str:
        return sha256(self.verifier)

    def verify(self, challenge: str) -> bool:
        if challenge is None:
            return False
        return secrets.compare_digest(self.challenge, challenge)


@dataclass
class ScopePermission:
    resource: str
    actions: Set[str]
    items: Set[str]

    @classmethod
    def from_string(cls, scope_str: str) -> 'ScopePermission':
        parts = scope_str.split(':') if scope_str else None
        if not parts or not 1 <= len(parts) <= 3:
            raise ValueError(f'Invalid scope {scope_str}')
        resource = parts[0]
        actions = set()
        items = set()
        size = len(parts)
        if size > 1:
            actions.update(parts[1].split(','))
            if 'write' in actions:
                # implies read
                actions.add('read')
        if size > 2:
            items.update(parts[2].split(','))

        return ScopePermission(resource, actions, items)

    def allows(self, other: 'ScopePermission'):
        if not (self.resource == '*' or self.resource == other.resource):
            return False
        if other.actions:
            if not (self.actions == {'*'} or self.actions >= other.actions):
                return False
        if other.items:
            if not (self.items == {'*'} or self.items >= other.items):
                return False
        return True


class OAuth2ClientCredentials(OAuth2):
    def __init__(
            self,
            tokenUrl: str,
            scheme_name: Optional[str] = None,
            scopes: Optional[Dict[str, str]] = None,
            auto_error: bool = False,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(clientCredentials={'tokenUrl': tokenUrl, 'scopes': scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get('Authorization')
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != 'bearer':
            return None
        return param


oauth2_token = OAuth2ClientCredentials(
    tokenUrl=f'{app_config.PATH_PREFIX}/v1/auth/oauth/token',
    auto_error=False
)


def hash_password(password_plain: str) -> str:
    return pwd_context.hash(password_plain)


def verify_password(password_plain: str, password_hash: str) -> bool:
    return pwd_context.verify(password_plain, password_hash)


async def authorize(
        request: Request,
        scopes: SecurityScopes,
        bearer_token: str = Depends(oauth2_token),
):
    logger.info('authorize(bearer_token=[%s], scopes=[%s])',
                bearer_token, scopes.scope_str)

    try:
        if bearer_token:
            auth_user = await auth_user_from_token(bearer_token)
        else:
            session_auth_user = request.session.get('au')
            logger.info('Session auth_user: %s', session_auth_user)
            auth_user = schemas.AuthUser.parse_obj(session_auth_user)
    except (LookupError, ValueError, authlib.jose.errors.JoseError) as exc:
        logger.info('get_user_task failed: %r', exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    else:
        if not can_access(auth_user, scopes.scopes):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        request.state.auth_user = auth_user


def create_auth_user_token(auth_user: schemas.AuthUser, expires_in: int = -1) -> str:
    payload = {
        'sub': auth_user.id,
        'client_id': auth_user.client_id,
        'scopes': auth_user.scopes,
    }
    return create_token(payload, expires_in)


def create_scale_user_token(scale_user: schemas.ScaleUser, expires_in: int = -1) -> str:
    payload = {
        'sub': scale_user.id,
        # TODO: legacy claim used by dotnet
        # TODO: delete this after moving the front-end to use `email` claim
        'unique_name': scale_user.email,
        'email': scale_user.email,
        'roles': scale_user.roles,
    }
    return create_token(payload, expires_in)


def create_token(payload: dict, expires_in: int = -1) -> str:
    if expires_in == -1:
        expires_in = app_config.OAUTH_ACCESS_TOKEN_EXPIRY
    issued_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
    expires_at = issued_at + datetime.timedelta(seconds=expires_in)
    payload['iat'] = issued_at
    payload['exp'] = expires_at
    payload['iss'] = JWT_ISSUER
    payload['aud'] = JWT_ISSUER
    token = JWT.encode(
        header={'alg': app_config.JWT_ALGORITHM},
        payload=payload,
        key=app_config.SECRET_KEY
    )
    return token.decode(encoding='ascii')


async def auth_user_from_token(token: str) -> schemas.AuthUser:
    if not token:
        raise ValueError('token value required')
    claims = JWT.decode(
        token,
        key=JWT_KEY,
        claims_options=AUTH_USER_TOKEN_OPTS
    )
    claims.validate(leeway=30)
    if claims.get('client_id'):
        auth_user = schemas.AuthUser(
            id=claims['sub'],
            client_id=claims['client_id'],
            client_secret_hash='none',
            scopes=claims['scopes'],
        )
    else:
        auth_user = schemas.AuthUser(
            id=claims['sub'],
            client_id=claims['email'],
            client_secret_hash='none',
            scopes=[f'role:{r}' for r in claims['roles']]
        )
    return auth_user


def can_access(auth_user: schemas.AuthUser, scopes: Optional[List[str]]) -> bool:
    if not auth_user.is_active:
        return False
    if auth_user.is_superuser:
        return True
    if not scopes:
        return True
    if not auth_user.scopes:
        return False
    logger.info('Verifying user %s has scopes %s', auth_user, scopes)
    user_permissions = [ScopePermission.from_string(s) for s in auth_user.scopes]
    for required_perm in [ScopePermission.from_string(s) for s in scopes]:
        for user_perm in user_permissions:
            if user_perm.allows(required_perm):
                break
        else:
            return False
    return True


def sha256(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    hashed = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.rstrip(b'=').decode('ascii')

"""
Authentication and authorization

There are two main types of "users" that are handled by this module.

    AuthUser
    ScaleUser

An ``AuthUser`` is a user/client defined in this application's database
and is a user/client that can access the API for development or administration
of the application. This type of user is authenticated from a username and
password stored locally or via Single Sign-On (SSO).

A ``ScaleUser`` is a user that launched this application from a Learning
Management System (LMS) such as Canvas and have been authenticated via
Learning Tools Interoperability (LTI).
"""
import datetime
import logging
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

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
    keys,
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
}

JWT = jose.JsonWebToken([app_config.JWT_ALGORITHM])

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


@dataclass
class ScopePermission:
    """Represents a permission to a particular resource.

    We use simple colon ``:`` separated strings to represent a permission
    to a particular resource along with permitted actions and optionally
    a set of permitted items.

    For example:
        platform:write (write and implies read)
        platform:read (read-only)
        platform:* (read/write/delete)
        platform:read:ae09b1a3c9ff4102a9953a1301bc9e11,87e927ab1abb46d6868760f7a081c178

    The last scope provides permission to read only the two specified
    platforms (by id).

    Note that scopes are also used in some cases to store other information
    such as roles, ``role:Instructor``.
    """
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
    """OAuth 2.0 Client Credentials flow.

    This is mainly used by the openapi docs in order to prompt for a
    ``client_id`` and ``client_secret`` when authenticating for the docs
    "Try It" feature.
    """
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
    """Returns a hashed string suitable for storing in a database."""
    return pwd_context.hash(password_plain)


def verify_password(password_plain: str, password_hash: str) -> bool:
    """Returns True if the plain string matches the provided hash."""
    return pwd_context.verify(password_plain, password_hash)


async def authorize(
        request: Request,
        scopes: SecurityScopes,
        bearer_token: str = Depends(oauth2_token),
):
    """Main security dependency for routes requiring authentication.

    All routes defined in ``scale_api.routes`` that require authentication
    and authorization depend on this function. This function first looks
    for auth info in the form of a Bearer token in the ``Authorization``
    HTTP Header. It falls back to looking in the request session.
    """
    logger.info('authorize(bearer_token=[%s], scopes=[%s])',
                bearer_token, scopes.scope_str)

    try:
        if bearer_token:
            auth_user = await auth_user_from_token(bearer_token)
            logger.info('authorize from bearer token AuthUser: %s', auth_user)
        else:
            session_auth_user = request.session.get('au')
            auth_user = schemas.AuthUser.parse_obj(session_auth_user)
            logger.info('authorize from session AuthUser: %s', session_auth_user)
    except (LookupError, ValueError, authlib.jose.errors.JoseError) as exc:
        logger.info('authorize failed: %r', exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    else:
        if not can_access(auth_user, scopes.scopes):
            logger.error('authorize access failure, AuthUser: %s, Scopes: %s',
                         auth_user, scopes.scopes)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        request.state.auth_user = auth_user


def create_auth_user_token(auth_user: schemas.AuthUser, expires_in: int = -1) -> str:
    """Returns an access token (JWT) for an ``AuthUser``."""
    payload = {
        'sub': auth_user.id,
        'client_id': auth_user.client_id,
        'scopes': auth_user.scopes,
    }
    return create_token(payload, expires_in)


def create_scale_user_token(scale_user: schemas.ScaleUser, expires_in: int = -1) -> str:
    """Returns an access token (JWT) for a ``ScaleUser``.

    This token is also used by the front-end web app to gather role and
    course info for the user.
    """
    payload = {
        'sub': scale_user.id,
        # TODO: legacy claim used by dotnet
        # TODO: delete this after moving the front-end to use `email` claim
        'unique_name': scale_user.email,
        'email': scale_user.email,
        'roles': scale_user.roles,
        'context': scale_user.context,
    }
    return create_token(payload, expires_in)


def create_token(payload: dict, expires_in: int = -1) -> str:
    """Returns a JWT signed with a secret key.

    Tokens returned from this function are meant to only be validated
    by this application and not externally, so that is why an RSA key is
    not used. The Issuer and Audience for this JWT are set to this app.
    """
    if expires_in == -1:
        expires_in = app_config.OAUTH_ACCESS_TOKEN_EXPIRY
    issued_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=5)
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
    """Returns an ``AuthUser`` from the provided JWT.

    This functions handles tokens that were generated for either an
    ``AuthUser`` or a ``ScaleUser``. For a ``ScaleUser``, the roles
    are set as scopes (i.e., role:Learner). This way endpoints can
    specify role scopes in addition to resource:action based scopes.
    """
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
    """Returns True if the user has the required scope(s)."""
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


# TODO: this might make sense to live in the lti.services module
async def create_platform_token(platform: schemas.Platform) -> str:
    """Returns a JWT used to call LTI Advantage Services.

    LTI Advantage Services such as the Names and Role Provisioning,
    Deep Linking and Assignment and Grade Services use ``client_credentials``
    flow with the ``urn:ietf:params:oauth:client-assertion-type:jwt-bearer``
    assertion type. This function generates the appropriate JWT bearer
    to use for requesting an access token for these services.
    """
    payload = {
        'iss': platform.client_id,
        'sub': platform.client_id,
        'aud': str(platform.auth_token_url),
        'iat': datetime.datetime.utcnow() - datetime.timedelta(seconds=5),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60),
        'jti': str(uuid.uuid4()),
    }
    private_key = await keys.private_key()
    header = {'typ': 'JWT', 'alg': 'RS256', 'kid': private_key.thumbprint()}
    return jose.jwt.encode(header, payload, private_key).decode('ascii')

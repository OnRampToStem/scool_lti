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

import logging
import time
from dataclasses import dataclass
from typing import Annotated, Any, NamedTuple, Self

import joserfc.errors
import joserfc.jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlowClientCredentials
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
    OAuth2,
    SecurityScopes,
)
from fastapi.security.utils import get_authorization_scheme_param
from passlib.context import CryptContext

from . import db, schemas, settings

logger = logging.getLogger(__name__)

JWT_KEY = settings.api.secret_key
JWT_ALGORITHM = settings.api.jwt_algorithm
JWT_ISSUER = settings.api.jwt_issuer
JWT_AUTH_USER_TOKEN_OPTS: dict[str, joserfc.jwt.ClaimsOption] = {
    "iss": {"essential": True, "value": JWT_ISSUER},
    "aud": {"essential": True, "value": JWT_ISSUER},
    "sub": {"essential": True},
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthorizeError(Exception):
    pass


class AuthUsers(NamedTuple):
    auth_user: schemas.AuthUser
    scale_user: schemas.ScaleUser


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
    actions: set[str]
    items: set[str]

    @classmethod
    def from_string(cls, scope_str: str) -> Self:
        parts = scope_str.split(":") if scope_str else None
        if not parts or not 1 <= len(parts) <= 3:  # noqa: PLR2004
            raise ValueError("SCOPE", scope_str)
        resource = parts[0]
        actions = set()
        items = set()
        size = len(parts)
        if size > 1:
            actions.update(parts[1].split(","))
            if "write" in actions:
                # implies read
                actions.add("read")
        if size > 2:  # noqa: PLR2004
            items.update(parts[2].split(","))

        return cls(resource, actions, items)

    def allows(self, other: Self) -> bool:
        if self.resource not in ("*", other.resource):
            return False
        if other.actions:
            return self.actions == {"*"} or self.actions >= other.actions
        if other.items:
            return self.items == {"*"} or self.items >= other.items
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
        scheme_name: str | None = None,
        scopes: dict[str, str] | None = None,
        auto_error: bool = False,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(
            clientCredentials=OAuthFlowClientCredentials(
                tokenUrl=tokenUrl,
                scopes=scopes,
            )
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> str | None:
        authorization = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            return None
        return param


oauth2_token = OAuth2ClientCredentials(
    tokenUrl=f"{settings.api.path_prefix}/v1/auth/oauth/token", auto_error=False
)
OAuth2Token = Annotated[str | None, Depends(oauth2_token)]

# We also support HTTP Basic auth as a fallback for Bearer tokens
HTTPBasicCreds = Annotated[
    HTTPBasicCredentials | None, Depends(HTTPBasic(auto_error=False))
]


async def authorize(
    request: Request,
    scopes: SecurityScopes,
    bearer_token: OAuth2Token,
    basic_creds: HTTPBasicCreds,
) -> AuthUsers:
    """Main security dependency for routes requiring authentication.

    All routes defined in ``scale_api.routes`` that require authentication
    and authorization depend on this function. This function first looks
    for auth info in the form of a Bearer token in the ``Authorization``
    HTTP Header. It falls back to looking for Basic Auth creds.

    If the request is both authenticated and authorized the following state
    values will be set on the request:

        request.state.auth_user
        request.state.scale_user

    If no ``scale_user`` is found the ``auth_user`` will be converted to a
    ``scale_user`` so both state values will always be set for any routes
    that use this as a dependency.
    """
    state = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    logger.info(
        "[%s]: authorize(bearer_token=[%s], basic_creds=[%s], scopes=[%s])",
        state,
        bearer_token,
        basic_creds.username if basic_creds else None,
        scopes.scope_str,
    )

    try:
        auth_user = await auth_user_from(bearer_token, basic_creds, state)
    except AuthorizeError as exc:
        logger.warning("[%s]: authorize failed: %r", state, exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        ) from None

    if not can_access(auth_user, scopes.scopes):
        logger.error(
            "[%s]: authorize access failure, AuthUser: %s, Scopes: %s",
            state,
            auth_user,
            scopes.scopes,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    request.state.auth_user = auth_user
    scale_user = schemas.ScaleUser.from_auth_user(auth_user)
    request.state.scale_user = scale_user

    return AuthUsers(auth_user, scale_user)


async def req_scale_user(
    auth_users: Annotated[AuthUsers, Depends(authorize)]
) -> schemas.ScaleUser:
    """Dependency that routes can use that depend on a ``scale_user``."""
    return auth_users.scale_user


async def auth_user_from(
    bearer_token: str | None,
    basic_creds: HTTPBasicCredentials | None,
    state: str,
) -> schemas.AuthUser:
    if bearer_token is not None:
        auth_user = auth_user_from_token(bearer_token)
        logger.info("[%s]: authorize from bearer token %r", state, auth_user)
    elif basic_creds is not None:
        auth_user = await auth_user_from_basic_creds(basic_creds)
        logger.info("[%s]: authorize from basic auth %r", state, auth_user)
    else:
        raise AuthorizeError("CREDENTIALS_REQUIRED")

    return auth_user


def auth_user_from_token(token: str) -> schemas.AuthUser:
    """Returns an ``AuthUser`` from the provided JWT.

    This functions handles tokens that were generated for either an
    ``AuthUser`` or a ``ScaleUser``. For a ``ScaleUser``, the roles
    are set as scopes (i.e., role:Learner). This way endpoints can
    specify role scopes in addition to resource:action based scopes.
    """
    if not token:
        raise AuthorizeError("TOKEN_REQUIRED")

    try:
        jwt_token = joserfc.jwt.decode(
            value=token, key=JWT_KEY, algorithms=[JWT_ALGORITHM]
        )
    except joserfc.errors.JoseError:
        logger.exception("token decode failed: %s", token)
        raise AuthorizeError("TOKEN_FORMAT") from None
    else:
        claims = jwt_token.claims

    try:
        joserfc.jwt.JWTClaimsRegistry(
            now=None, leeway=30, **JWT_AUTH_USER_TOKEN_OPTS
        ).validate(claims)
    except joserfc.errors.JoseError:
        logger.exception("token claim validation failed: %s", claims)
        raise AuthorizeError("TOKEN_CLAIMS") from None

    if client_id := claims.get("client_id"):
        scopes = claims["scopes"]
    else:
        client_id = claims["email"]
        scopes = [f"role:{r}" for r in claims["roles"]]

    return schemas.AuthUser(
        id=claims["sub"],
        client_id=client_id,
        client_secret_hash="none",  # noqa: S106
        scopes=scopes,
        context=claims["context"],
    )


async def auth_user_from_basic_creds(
    basic_creds: HTTPBasicCredentials,
) -> schemas.AuthUser:
    try:
        auth_user = await db.store.user_by_client_id(client_id=basic_creds.username)
    except LookupError:
        raise AuthorizeError("USER_NOT_FOUND", basic_creds.username) from None
    else:
        if not verify_password(basic_creds.password, auth_user.client_secret_hash):
            raise AuthorizeError("PASSWORD_MISMATCH")
        return auth_user


def can_access(auth_user: schemas.AuthUser, scopes: list[str] | None) -> bool:
    """Returns True if the user has the required scope(s)."""
    if not auth_user.is_active:
        return False
    if auth_user.is_superuser:
        return True
    if not scopes:
        return True
    if not auth_user.scopes:
        return False
    logger.info("Verifying user %s has scopes %s", auth_user, scopes)
    user_permissions = [ScopePermission.from_string(s) for s in auth_user.scopes]
    for required_perm in [ScopePermission.from_string(s) for s in scopes]:
        for user_perm in user_permissions:
            if user_perm.allows(required_perm):
                break
        else:
            return False
    return True


def create_auth_user_token(auth_user: schemas.AuthUser, expires_in: int = -1) -> str:
    """Returns an access token (JWT) for an ``AuthUser``."""
    payload = {
        "sub": auth_user.id,
        "client_id": auth_user.client_id,
        "scopes": auth_user.scopes,
        "context": auth_user.context,
    }
    return create_token(payload, expires_in)


def create_scale_user_token(scale_user: schemas.ScaleUser, expires_in: int = -1) -> str:
    """Returns an access token (JWT) for a ``ScaleUser``.

    This token is also used by the front-end web app to gather role and
    course info for the user.
    """
    payload = {
        "sub": scale_user.id,
        "email": scale_user.email,
        "name": scale_user.name,
        "roles": scale_user.roles,
        "context": scale_user.context,
    }
    # TODO: delete this after moving the front-end to use `email` claim
    if settings.features.legacy_unique_name_claim:
        payload["unique_name"] = scale_user.email
    if scale_user.picture:
        payload["picture"] = scale_user.picture
    return create_token(payload, expires_in)


def create_token(payload: dict[str, Any], expires_in: int = -1) -> str:
    """Returns a JWT signed with a secret key.

    Tokens returned from this function are meant to only be validated
    by this application and not externally, so that is why an RSA key is
    not used. The Issuer and Audience for this JWT are set to this app.
    """
    if expires_in == -1:
        expires_in = settings.api.oauth_access_token_expiry
    now = int(time.time())
    issued_at = now - 5
    expires_at = now + expires_in
    payload["iat"] = issued_at
    payload["exp"] = expires_at
    payload["iss"] = JWT_ISSUER
    payload["aud"] = JWT_ISSUER
    return joserfc.jwt.encode(
        header={"alg": JWT_ALGORITHM},
        claims=payload,
        key=JWT_KEY,
    )


def hash_password(password_plain: str) -> str:
    """Returns a hashed string suitable for storing in a database."""
    return pwd_context.hash(password_plain)


def verify_password(password_plain: str, password_hash: str) -> bool:
    """Returns True if the plain string matches the provided hash."""
    return pwd_context.verify(password_plain, password_hash)

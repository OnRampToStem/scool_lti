# Student Centered Open Online Learning (SCOOL) LTI Integration
# Copyright (c) 2021-2024  Fresno State University, SCOOL Project Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import datetime
import logging

import sqlalchemy as sa
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    validates,
)

from .core import new_uuid

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class Platform(Base):
    """A Learning Management Systems (LMS) platform.

    This represents an LMS with respect to all the information required
    in order to connect with it using LTI 1.3.

    Note that some LMS vendors such as Canvas use the same `issuer`` URL
    for all installations. So the ``issuer`` field can not be assumed to be
    a unique identifier.
    """

    __tablename__ = "platforms"

    id: Mapped[str] = mapped_column(sa.String(32), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(sa.String(100))
    issuer: Mapped[str | None]
    oidc_auth_url: Mapped[str | None]
    auth_token_url: Mapped[str | None]
    jwks_url: Mapped[str | None]
    client_id: Mapped[str | None] = mapped_column(sa.String(128))
    client_secret: Mapped[str | None] = mapped_column(sa.String(128))

    def __repr__(self) -> str:
        return f"Platform(id={self.id!r}, name={self.name!r})"


class AuthUser(Base):
    """Authorized User.

    This represents a local user/client account that can be authorized
    for endpoints. This is distinct from a ``ScoolUser`` which is authorized
    using LTI.
    """

    __tablename__ = "auth_users"

    id: Mapped[str] = mapped_column(sa.String(32), primary_key=True, default=new_uuid)
    client_id: Mapped[str] = mapped_column(sa.String(128), unique=True)
    client_secret_hash: Mapped[str] = mapped_column(sa.String(128))
    scopes: Mapped[str | None]
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, default=sa.func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()
    )

    # noinspection PyUnusedLocal
    @validates("client_id")
    def normalize_client_id(  # type: ignore[no-untyped-def]
        self,
        key,  # noqa: ARG002
        value: str,
    ) -> str:
        """Ensure we always store the ``client_id`` in lowercase."""
        return value.lower()

    def __repr__(self) -> str:
        return f"AuthUser(client_id={self.client_id!r}, is_active={self.is_active})"


class AuthJsonWeKey(Base):
    """JSON Web Keys.

    This represents the JSON Web Key(s) used by this application, primarily
    for LTI integration. When configuring LTI a JSON Web Key or JWKS URL
    must be provided to the Platform. This key or URL is used by the Platform
    to validate JWT Bearer tokens provided in order to gain access tokens
    when calling LTI Advantage Services.
    """

    __tablename__ = "auth_jwks"

    kid: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    data: Mapped[str]
    valid_from: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, default=sa.func.now()
    )
    valid_to: Mapped[datetime.datetime | None]

    def __repr__(self) -> str:
        return (
            "AuthJsonWeKey("
            f"kid={self.kid!r}"
            f", valid_from={self.valid_from}"
            f", valid_to={self.valid_to}"
            ")"
        )


class Cache(Base):
    """Cache table.

    Used to temporarily cache entries. This is used in placed of a service
    like Redis or Memcache and avoids needing to use in-memory storage
    for cache. While slower, this enables this application to remain
    stateless and avoids the complexity of relying on other services. Given
    the anticipated use of this application, using a database-backed cache
    table seems appropriate.
    """

    __tablename__ = "cache_objects"

    key: Mapped[str] = mapped_column(sa.String(255), primary_key=True)
    ttl: Mapped[int] = mapped_column(sa.Integer, default=3600)
    ttl_type: Mapped[str] = mapped_column(sa.String(10), default="fixed")
    expire_at: Mapped[datetime.datetime]
    value: Mapped[str]

    def __repr__(self) -> str:
        return (
            f"Cached(key={self.key!r}, "
            f"ttl={self.ttl}, "
            f"ttl_type={self.ttl_type}, "
            f"expire_at={self.expire_at}, "
            ")"
        )

import datetime
import logging

from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    validates,
)

from .core import new_uuid, sa

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
    __tablename__ = 'platforms'

    id: Mapped[str] = mapped_column(
        sa.String(32), primary_key=True, default=new_uuid
    )
    name: Mapped[str] = mapped_column(sa.String(100))
    issuer: Mapped[str | None]
    oidc_auth_url: Mapped[str | None]
    auth_token_url: Mapped[str | None]
    jwks_url: Mapped[str | None]
    client_id: Mapped[str | None] = mapped_column(sa.String(128))
    client_secret: Mapped[str | None] = mapped_column(sa.String(128))

    # TODO: should there be a `PlatformDeployment` model in case the tool is
    #  deployed multiple times??

    def __repr__(self) -> str:
        return f'Platform(id={self.id!r}, name={self.name!r})'


class AuthUser(Base):
    """Authorized User.

    This represents a local user/client account that can be authorized
    for endpoints. This is distinct from a ``ScaleUser`` which is authorized
    using LTI.
    """
    __tablename__ = 'auth_users'

    id: Mapped[str] = mapped_column(
        sa.String(32), primary_key=True, default=new_uuid
    )
    client_id: Mapped[str] = mapped_column(
        sa.String(128), unique=True
    )
    client_secret_hash: Mapped[str | None] = mapped_column(sa.String(128))
    scopes: Mapped[str | None]
    is_active: Mapped[bool | None] = mapped_column(sa.Boolean, default=True)
    is_verified: Mapped[bool | None] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now()
    )
    updated_at: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()
    )

    @validates('client_id')
    def normalize_client_id(
            self,
            key,  # noqa key not used
            value: str,
    ) -> str:
        """Ensure we always store the ``client_id`` in lowercase."""
        return value.lower()

    def __repr__(self) -> str:
        return (
            'AuthUser('
            f'client_id={self.client_id!r}'
            f', is_active={self.is_active}'
            f', is_verified={self.is_verified}'
            ')'
        )


class AuthJsonWeKey(Base):
    """JSON Web Keys.

    This represents the JSON Web Key(s) used by this application, primarily
    for LTI integration. When configuring LTI a JSON Web Key or JWKS URL
    must be provided to the Platform. This key or URL is used by the Platform
    to validate JWT Bearer tokens provided in order to gain access tokens
    when calling LTI Advantage Services.
    """
    __tablename__ = 'auth_jwks'

    kid: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    data: Mapped[str]
    valid_from: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now()
    )
    valid_to: Mapped[datetime.datetime | None]

    def __repr__(self) -> str:
        return (
            'AuthJsonWeKey('
            f'kid={self.kid!r}'
            f', valid_from={self.valid_from}'
            f', valid_to={self.valid_to}'
            ')'
        )


class Message(Base):
    """A generic message store.

    This represents a generic text blob storage.
    """
    __tablename__ = 'messages'

    id: Mapped[str] = mapped_column(
        sa.String(255), primary_key=True, default=new_uuid
    )
    subject: Mapped[str | None] = mapped_column(sa.String(255), index=True)
    header: Mapped[str | None]
    body: Mapped[str | None]
    status: Mapped[str | None] = mapped_column(sa.String(10), default='active')
    created_at: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now()
    )
    updated_at: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()
    )

    def __repr__(self) -> str:
        return (
            'Message('
            f'id={self.id!r}'
            f', subject={self.subject!r}'
            f', status={self.status!r}'
            ')'
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
    __tablename__ = 'cache_objects'

    key: Mapped[str] = mapped_column(sa.String(255), primary_key=True)
    ttl: Mapped[int | None] = mapped_column(sa.Integer, default=3600)
    ttl_type: Mapped[str | None] = mapped_column(sa.String(10), default='fixed')
    expire_at: Mapped[datetime.datetime | None]
    value: Mapped[str | None]

    def __repr__(self) -> str:
        return (
            f'Cached(key={self.key!r}, '
            f'ttl={self.ttl}, '
            f'ttl_type={self.ttl_type}, '
            f'expire_at={self.expire_at}, '
            f')'
        )


class BinData(Base):
    """Binary Data table.

    Designed to store any arbitrary binary data, but primarily used in order
    to store file attachments.
    """
    __tablename__ = 'bin_data'

    id: Mapped[str] = mapped_column(
        sa.String(255), primary_key=True, default=new_uuid
    )
    content_type: Mapped[str | None] = mapped_column(
        sa.String(255), default='application/octet-stream'
    )
    name: Mapped[str | None] = mapped_column(sa.String(255))
    status: Mapped[str | None] = mapped_column(sa.String(10), default='active')
    created_at: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now()
    )
    updated_at: Mapped[datetime.datetime | None] = mapped_column(
        sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()
    )
    data = mapped_column(sa.LargeBinary())

    def __repr__(self) -> str:
        return (
            'BinData('
            f'id={self.id!r}'
            f', content_type={self.content_type!r}'
            f', name={self.name!r}'
            f', status={self.status!r}'
            ')'
        )

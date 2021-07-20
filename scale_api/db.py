"""
SCALE API Database

This module defines the models and repositories used to store data
for this application.
"""
import datetime
import logging
import uuid
from typing import Callable, List, Mapping, TypeVar, Union

import sqlalchemy as sa
import sqlalchemy.exc
import sqlalchemy.ext.declarative
import sqlalchemy.orm

from scale_api import (
    aio,
    app_config,
    schemas,
)

T = TypeVar('T')

logger = logging.getLogger(__name__)

Session = sqlalchemy.orm.Session

engine = sa.create_engine(
    app_config.DB_URL,
    future=True,
    echo=app_config.DEBUG_DB,
)

SessionLocal = sqlalchemy.orm.sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True
)

Base = sqlalchemy.ext.declarative.declarative_base()


def new_uuid() -> str:
    """Return a UUID as a 32-character hex string."""
    return uuid.uuid4().hex


class Platform(Base):
    """An Learning Management Systems (LMS) platform.

    This represents an LMS with respect to all the information required
    in order to connect with it using LTI 1.3.

    Note that some LMS vendors such as Canvas use the same `issuer`` URL
    for all installations. So the ``issuer`` field can not be assumed to be
    a unique identifier.
    """
    __tablename__ = 'platforms'

    id = sa.Column(sa.String(32), primary_key=True, default=new_uuid)
    name = sa.Column(sa.String(100), nullable=False)
    issuer = sa.Column(sa.Text())
    oidc_auth_url = sa.Column(sa.Text())
    auth_token_url = sa.Column(sa.Text(), nullable=True)
    jwks_url = sa.Column(sa.Text())
    client_id = sa.Column(sa.String(128), nullable=True)
    client_secret = sa.Column(sa.String(128), nullable=True)

    # TODO: should there be a `PlatformDeployment` model in case the tool is deployed multiple times??

    def __repr__(self) -> str:
        return f'Platform(id={self.id!r}, name={self.name!r})'


class AuthUser(Base):
    """Authorized User.

    This represents a local user/client account that can be authorized
    for endpoints. This is distinct from a ``ScaleUser`` which is authorized
    using LTI.
    """
    __tablename__ = 'auth_users'

    id = sa.Column(sa.String(32), primary_key=True, default=new_uuid)
    client_id = sa.Column(sa.String(128), unique=True, nullable=False)
    client_secret_hash = sa.Column(sa.String(128), nullable=True)
    scopes = sa.Column(sa.Text, nullable=True)
    is_active = sa.Column(sa.Boolean(), default=True)
    is_verified = sa.Column(sa.Boolean, default=False)
    created_at = sa.Column(sa.DateTime, default=sa.func.now())
    updated_at = sa.Column(sa.DateTime, default=sa.func.now(), onupdate=sa.func.now())

    @sqlalchemy.orm.validates('client_id')
    def normalize_client_id(self, key, value):
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

    kid = sa.Column(sa.String(64), primary_key=True)
    data = sa.Column(sa.Text, nullable=False)
    valid_from = sa.Column(sa.DateTime, default=sa.func.now())
    valid_to = sa.Column(sa.DateTime, nullable=True)

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

    id = sa.Column(sa.String(255), primary_key=True, default=new_uuid)
    subject = sa.Column(sa.String(255), index=True)
    header = sa.Column(sa.Text, nullable=True)
    body = sa.Column(sa.Text)
    status = sa.Column(sa.String(10), default='active')
    created_at = sa.Column(sa.DateTime, default=sa.func.now())
    updated_at = sa.Column(sa.DateTime, default=sa.func.now(), onupdate=sa.func.now())

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

    key = sa.Column(sa.String(255), primary_key=True)
    ttl = sa.Column(sa.Integer, default=3600)
    ttl_type = sa.Column(sa.String(10), default='fixed')
    expire_at = sa.Column(sa.DateTime)
    value = sa.Column(sa.Text)

    def __repr__(self) -> str:
        return (
            f'Cached(key={self.key!r}, '
            f'ttl={self.ttl}, '
            f'ttl_type={self.ttl_type}, '
            f'expire_at={self.expire_at}, '
            f')'
        )


class ScaleStore:
    """SCALE Application Repository."""

    def platforms(self) -> List[schemas.Platform]:
        stmt = sa.select(Platform)
        with SessionLocal() as session:
            result = session.execute(stmt)
            platforms = [
                schemas.Platform.from_orm(row)
                for row in result.scalars()
            ]

        return platforms

    def platform(self, platform_id: str) -> schemas.Platform:
        stmt = sa.select(Platform).where(Platform.id == platform_id)
        with SessionLocal() as session:
            result = session.execute(stmt).scalar()
            if not result:
                raise LookupError(platform_id)
            platform = schemas.Platform.from_orm(result)

        return platform

    def user(self, user_id: str) -> schemas.AuthUser:
        with SessionLocal() as session:
            result = session.get(AuthUser, user_id)
            if not result:
                raise LookupError(user_id)
            user = schemas.AuthUser.from_orm(result)

        return user

    def user_by_client_id(self, client_id: str) -> schemas.AuthUser:
        stmt = sa.select(AuthUser).where(
            sa.func.lower(AuthUser.client_id) == client_id.lower()
            and not AuthUser.disabled
        )
        with SessionLocal() as session:
            result = session.execute(stmt).scalar()
            if not result:
                raise LookupError(client_id)
            user = schemas.AuthUser.from_orm(result)

        return user

    def json_web_keys(self) -> List[schemas.AuthJsonWebKey]:
        stmt = sa.select(AuthJsonWeKey).where(
            AuthJsonWeKey.valid_from <= sa.func.now(),
            sa.or_(
                AuthJsonWeKey.valid_to == None,
                AuthJsonWeKey.valid_to > sa.func.now(),
            )
        )
        with SessionLocal() as session:
            result = session.execute(stmt).scalars()
            keys = [
                schemas.AuthJsonWebKey.from_orm(row)
                for row in result
            ]

        return keys

    platforms_async = aio.wrap(platforms)
    platform_async = aio.wrap(platform)
    user_async = aio.wrap(user)
    user_by_client_id_async = aio.wrap(user_by_client_id)
    json_web_keys_async = aio.wrap(json_web_keys)


class MessageStore:
    """Messages Repository."""

    def messages(self, subject: str) -> List[schemas.Message]:
        stmt = sa.select(Message).where(
            Message.subject == subject,
            Message.status == 'active',
        )
        with SessionLocal() as session:
            result = session.execute(stmt)
            entry_list = [
                schemas.Message.from_orm(row)
                for row in result.scalars()
            ]

        return entry_list

    def message(self, msg_id: str, subject: str) -> schemas.Message:
        with SessionLocal() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if msg.subject != subject:
                raise ValueError(f'Update subject mismatch: actual %s, expected: %s',
                                 msg.subject, subject)
            return schemas.Message.from_orm(msg)

    def create(self, subject: str, body: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = Message(subject=subject, header=header, body=body)
            session.add(msg)
            session.flush()
            return schemas.Message.from_orm(msg)

    def update(self, msg_id: str, subject: str, body: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if msg.subject != subject:
                raise ValueError(f'Update subject mismatch: actual %s, expected: %s',
                                 msg.subject, subject)
            if msg.header != header:
                raise ValueError(f'Update header mismatch: actual %s, expected: %s',
                                 msg.header, header)
            if msg.body != body:
                msg.body = body
            session.flush()
            return schemas.Message.from_orm(msg)

    def delete(self, msg_id: str, subject: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if not msg.subject.startswith(subject):
                raise ValueError(f'Delete aborted, mismatched subject: '
                                 'actual: [%s], expected: [%s]',
                                 msg.subject, subject)
            if header and msg.header != header:
                raise ValueError(f'Delete aborted, mismatched header: '
                                 'actual: [%s], expected: [%s]',
                                 msg.header, header)
            msg.status = 'deleted'
            session.flush()
            return schemas.Message.from_orm(msg)

    messages_async = aio.wrap(messages)
    message_async = aio.wrap(message)
    create_async = aio.wrap(create)
    update_async = aio.wrap(update)
    delete_async = aio.wrap(delete)


class UserStore:
    """Users Repository."""

    def users(self, subject: str) -> List[schemas.Message]:
        if subject.endswith('%'):
            stmt = sa.select(Message).where(
                Message.subject.like(subject),
                Message.status == 'active',
            )
        else:
            stmt = sa.select(Message).where(
                Message.subject == subject,
                Message.status == 'active',
            )
        with SessionLocal() as session:
            result = session.execute(stmt)
            entry_list = [
                schemas.Message.from_orm(row)
                for row in result.scalars()
            ]

        return entry_list

    def user(self, user_key: str) -> schemas.Message:
        with SessionLocal() as session:
            msg = session.get(Message, user_key)
            if not msg:
                raise LookupError(user_key)
            if not msg.subject.startswith('users.'):
                raise ValueError(f'Not a user entry: %s', msg.subject)
            return schemas.Message.from_orm(msg)

    def create(self, user_key: str, subject: str, body: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = Message(id=user_key, subject=subject, header=header, body=body)
            session.add(msg)
            session.flush()
            return schemas.Message.from_orm(msg)

    def update(self, user_key: str, subject: str, body: str) -> schemas.Message:
        with SessionLocal.begin() as session:
            user = session.get(Message, user_key)
            if not user:
                raise LookupError(user_key)
            if not user.subject.startswith(subject):
                raise ValueError(f'Update subject mismatch: actual %s, expected: %s',
                                 user.subject, subject)
            if user.body != body:
                user.body = body
            session.flush()
            return schemas.Message.from_orm(user)

    def delete(self, user_key: str, subject: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            user = session.get(Message, user_key)
            if not user:
                raise LookupError(user_key)
            if not user.subject.startswith(subject):
                raise ValueError(f'Delete aborted, mismatched subject: '
                                 'actual: [%s], expected: [%s]',
                                 user.subject, subject)
            if header and user.header != header:
                raise ValueError(f'Delete aborted, mismatched header: '
                                 'actual: [%s], expected: [%s]',
                                 user.header, header)
            user.status = 'deleted'
            session.flush()
            return schemas.Message.from_orm(user)

    users_async = aio.wrap(users)
    user_async = aio.wrap(user)
    create_async = aio.wrap(create)
    update_async = aio.wrap(update)
    delete_async = aio.wrap(delete)


class CacheStore:
    """Cache Repository."""
    TTL_DEFAULT = 3600
    TTL_TYPE_FIXED = 'fixed'
    TTL_TYPE_ROLLING = 'rolling'

    def __init__(self,
                 now_func: Callable[..., datetime.datetime] = datetime.datetime.utcnow) -> None:
        self.now = now_func
        self.next_purge_time = now_func()

    def _calc_expires(self, ttl: int) -> datetime.datetime:
        return self.now() + datetime.timedelta(seconds=ttl)

    def guid(self, prefix: str = '') -> str:
        return f'{prefix}{new_uuid()}'

    def add(self, key: str, value: str, *,
            ttl: int = TTL_DEFAULT,
            ttl_type: str = TTL_TYPE_FIXED,
            append_guid: bool = False) -> str:
        """Adds an entry to the cache else raises if the entry already exists."""
        key = self.guid(key) if append_guid else key
        self.add_many({key: value}, ttl=ttl, ttl_type=ttl_type)
        return key

    def add_many(self, data: Mapping[str, str], *,
                 ttl: int = TTL_DEFAULT,
                 ttl_type: str = TTL_TYPE_FIXED) -> None:
        """Adds entries to the cache else raises if any entry already exists."""
        self.purge_expired_safe()
        expire_at = self._calc_expires(ttl)
        entries = [
            Cache(
                key=k,
                value=v,
                ttl=ttl,
                ttl_type=ttl_type,
                expire_at=expire_at,
            )
            for k, v in data.items()
        ]
        try:
            with SessionLocal() as session:
                session.add_all(entries)
                session.commit()
        except Exception as exc:
            logger.warning('Cache.add_many failed, trying purge: %r', exc)
            self.purge_expired()
            # Retry after purging cache
            with SessionLocal() as session:
                session.add_all(entries)
                session.commit()

    def put(self, key: str, value: str, *,
            ttl: int = TTL_DEFAULT,
            ttl_type: str = TTL_TYPE_FIXED,
            append_guid: bool = False) -> str:
        """Updates an entry in the cache else creates a new entry."""
        key = self.guid(key) if append_guid else key
        self.put_many({key: value}, ttl=ttl, ttl_type=ttl_type)
        return key

    def put_many(self, data: Mapping[str, str], *,
                 ttl: int = TTL_DEFAULT,
                 ttl_type: str = TTL_TYPE_FIXED) -> None:
        """Updates entries in the cache else creates new entries."""
        self.purge_expired_safe()
        expire_at = self._calc_expires(ttl)
        entries = [
            Cache(
                key=k,
                value=v,
                ttl=ttl,
                ttl_type=ttl_type,
                expire_at=expire_at,
            )
            for k, v in data.items()
        ]
        with SessionLocal() as session:
            try:
                session.add_all(entries)
                session.commit()
            except sqlalchemy.exc.IntegrityError:
                session.rollback()
                # Do a purge so we don't try to update expired entries
                self.purge_expired()
                for new_entry in entries:
                    entry = session.get(Cache, new_entry.key)
                    if entry is None:
                        session.add(new_entry)
                    else:
                        entry.value = new_entry.value
                        entry.ttl = ttl
                        entry.ttl_type = ttl_type
                        entry.expire_at = expire_at
                session.commit()

    def get(self, key: str, default: T = None) -> Union[str, T]:
        """Returns an entry from the cache else ``default`` if no entry exists."""
        with SessionLocal() as session:
            entry = session.get(Cache, key)
            if entry:
                if entry.expire_at > self.now():
                    if entry.ttl_type == 'rolling':
                        entry.expire_at = self._calc_expires(entry.ttl)
                        session.commit()
                    value = entry.value
                else:
                    session.delete(entry)
                    session.commit()
                    value = default
            else:
                value = default

        return value

    def get_many(self, key_prefix: str) -> Mapping[str, str]:
        """Returns entries from the cache.

        The entries are returned in a dict where they key is the cache key
        and the value is cache value.
        """
        now = self.now()
        stmt = sa.select(Cache).where(Cache.key.ilike(key_prefix + '%'))
        with SessionLocal.begin() as session:
            entries = {}
            for entry in session.execute(stmt).scalars():
                if entry.expire_at > now:
                    entries[entry.key] = entry.value
                    if entry.ttl_type == 'rolling':
                        entry.expire_at = self._calc_expires(entry.ttl)
                else:
                    session.delete(entry)
        return entries

    def pop(self, key: str, default: T = None) -> Union[str, T]:
        """Returns an entry from the cache else ``default``.

        If the entry exists it will be removed from the cache.
        """
        with SessionLocal.begin() as session:
            entry = session.get(Cache, key)
            if entry is None:
                return default
            value = entry.value if entry.expire_at > self.now() else default
            session.delete(entry)
        return value

    def purge_expired(self) -> int:
        """Removes all entries that are expired."""
        stmt = sa.delete(Cache).where(Cache.expire_at <= self.now())
        with SessionLocal.begin() as session:
            rows_purged = session.execute(stmt).rowcount
        return rows_purged

    def purge_expired_safe(self) -> None:
        if self.now() < self.next_purge_time:
            return
        self.next_purge_time = self.now() + datetime.timedelta(seconds=self.TTL_DEFAULT)
        try:
            purge_count = self.purge_expired()
            logger.info('Cache.purge_expired count %s', purge_count)
        except Exception as exc:
            logger.warning('Cache.purge_expired failed: %r', exc)

    add_async = aio.wrap(add)
    add_many_async = aio.wrap(add_many)
    put_async = aio.wrap(put)
    put_many_async = aio.wrap(put_many)
    get_async = aio.wrap(get)
    get_many_async = aio.wrap(get_many)
    pop_async = aio.wrap(pop)
    purge_expired_async = aio.wrap(purge_expired)


store = ScaleStore()
message_store = MessageStore()
user_store = UserStore()
cache_store = CacheStore()

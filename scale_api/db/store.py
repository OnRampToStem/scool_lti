import datetime
import logging

import sqlalchemy as sa

from .. import schemas
from .core import IntegrityError, SessionLocal, new_uuid
from .models import AuthJsonWeKey, AuthUser, Cache, Platform

logger = logging.getLogger(__name__)

CACHE_TTL_DEFAULT = 3600
CACHE_TTL_TYPE_FIXED = "fixed"
CACHE_TTL_TYPE_ROLLING = "rolling"


def platforms() -> list[schemas.Platform]:
    stmt = sa.select(Platform)
    with SessionLocal() as session:
        result = session.execute(stmt)
        return [schemas.Platform.from_orm(row) for row in result.scalars()]


def platform(platform_id: str) -> schemas.Platform:
    stmt = sa.select(Platform).where(Platform.id == platform_id)
    with SessionLocal() as session:
        result = session.execute(stmt).scalar()
        if not result:
            raise LookupError(platform_id)
        return schemas.Platform.from_orm(result)


def user(user_id: str) -> schemas.AuthUser:
    with SessionLocal() as session:
        result = session.get(AuthUser, user_id)
        if not result:
            raise LookupError(user_id)
        return schemas.AuthUser.from_orm(result)


def user_by_client_id(client_id: str) -> schemas.AuthUser:
    stmt = sa.select(AuthUser).where(
        sa.func.lower(AuthUser.client_id) == client_id.lower() and AuthUser.is_active
    )
    with SessionLocal() as session:
        result = session.execute(stmt).scalar()
        if not result:
            raise LookupError(client_id)
        return schemas.AuthUser.from_orm(result)


def json_web_keys() -> list[schemas.AuthJsonWebKey]:
    stmt = sa.select(AuthJsonWeKey).where(
        AuthJsonWeKey.valid_from <= sa.func.now(),
        sa.or_(
            AuthJsonWeKey.valid_to.is_(None),
            AuthJsonWeKey.valid_to > sa.func.now(),
        ),
    )
    with SessionLocal() as session:
        result = session.execute(stmt).scalars()
        return [schemas.AuthJsonWebKey.from_orm(row) for row in result]


def cache_put(
    key: str,
    value: str,
    *,
    ttl: int = CACHE_TTL_DEFAULT,
    ttl_type: str = CACHE_TTL_TYPE_FIXED,
    append_guid: bool = False,
) -> str:
    """Updates an entry in the cache else creates a new entry."""
    _cache_purge_expired()
    key = _cache_guid(key) if append_guid else key
    expires_at = _cache_calc_expires(ttl)
    entry = Cache(
        key=key,
        value=value,
        ttl=ttl,
        ttl_type=ttl_type,
        expire_at=expires_at,
    )
    with SessionLocal() as session:
        try:
            session.add(entry)
            session.commit()
        except IntegrityError:
            session.rollback()
            if db_entry := session.get(Cache, key):
                db_entry.value = value
                db_entry.ttl = ttl
                db_entry.ttl_type = ttl_type
                db_entry.expire_at = expires_at
            else:
                session.add(entry)
            session.commit()

    return key


def cache_get(key: str, default: str | None = None) -> str | None:
    """Returns an entry from the cache else ``default`` if no entry exists."""
    with SessionLocal.begin() as session:
        if entry := session.get(Cache, key):
            if _cache_is_live(entry):
                if entry.ttl_type == CACHE_TTL_TYPE_ROLLING:
                    entry.expire_at = _cache_calc_expires(entry.ttl)
                return entry.value

            session.delete(entry)

    return default


def cache_pop(key: str, default: str | None = None) -> str | None:
    """Returns an entry from the cache else ``default``.

    If the entry exists it will be removed from the cache.
    """
    with SessionLocal.begin() as session:
        if (entry := session.get(Cache, key)) is None:
            value = default
        elif _cache_is_live(entry):
            value = entry.value
        else:
            value = default
        session.delete(entry)

    return value


def _cache_calc_expires(ttl: int) -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(seconds=ttl)


def _cache_is_live(entry: Cache) -> bool:
    expiry: datetime.datetime = entry.expire_at
    return expiry.replace(tzinfo=datetime.UTC) > datetime.datetime.now(tz=datetime.UTC)


def _cache_guid(prefix: str | None = None) -> str:
    if prefix is None:
        prefix = ""
    return f"{prefix}{new_uuid()}"


def _cache_purge_expired() -> None:
    """Removes all entries that are expired."""
    now = datetime.datetime.now(tz=datetime.UTC)
    stmt = sa.delete(Cache).where(Cache.expire_at <= now)
    with SessionLocal.begin() as session:
        session.execute(stmt)

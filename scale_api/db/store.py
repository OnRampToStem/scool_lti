import datetime
import logging

import sqlalchemy as sa

from .. import schemas
from .core import IntegrityError, async_session, new_uuid
from .models import AuthJsonWeKey, AuthUser, Cache, Platform

logger = logging.getLogger(__name__)

CACHE_TTL_DEFAULT = 3600
CACHE_TTL_TYPE_FIXED = "fixed"
CACHE_TTL_TYPE_ROLLING = "rolling"


async def platforms() -> list[schemas.Platform]:
    stmt = sa.select(Platform)
    async with async_session() as session:
        result = await session.execute(stmt)
        return [schemas.Platform.from_orm(row) for row in result.scalars()]


async def platform(platform_id: str) -> schemas.Platform:
    stmt = sa.select(Platform).where(Platform.id == platform_id)
    async with async_session() as session:
        if result := await session.execute(stmt):
            return schemas.Platform.from_orm(result.scalar())
        raise LookupError(platform_id)


async def user(user_id: str) -> schemas.AuthUser:
    async with async_session() as session:
        result = await session.get(AuthUser, user_id)
        if not result:
            raise LookupError(user_id)
        return schemas.AuthUser.from_orm(result)


async def user_by_client_id(client_id: str) -> schemas.AuthUser:
    stmt = sa.select(AuthUser).where(
        sa.func.lower(AuthUser.client_id) == client_id.lower() and AuthUser.is_active
    )
    async with async_session() as session:
        if result := await session.execute(stmt):
            return schemas.AuthUser.from_orm(result.scalar())
        raise LookupError(client_id)


async def json_web_keys() -> list[schemas.AuthJsonWebKey]:
    stmt = sa.select(AuthJsonWeKey).where(
        AuthJsonWeKey.valid_from <= sa.func.now(),
        sa.or_(
            AuthJsonWeKey.valid_to.is_(None),
            AuthJsonWeKey.valid_to > sa.func.now(),
        ),
    )
    async with async_session() as session:
        result = await session.execute(stmt)
        return [schemas.AuthJsonWebKey.from_orm(row) for row in result.scalars()]


async def cache_put(
    key: str,
    value: str,
    *,
    ttl: int = CACHE_TTL_DEFAULT,
    ttl_type: str = CACHE_TTL_TYPE_FIXED,
    append_guid: bool = False,
) -> str:
    """Updates an entry in the cache else creates a new entry."""
    await _cache_purge_expired()
    key = _cache_guid(key) if append_guid else key
    expires_at = _cache_calc_expires(ttl)
    entry = Cache(
        key=key,
        value=value,
        ttl=ttl,
        ttl_type=ttl_type,
        expire_at=expires_at,
    )
    async with async_session() as session:
        try:
            session.add(entry)
            await session.commit()
        except IntegrityError:
            await session.rollback()
            if db_entry := await session.get(Cache, key):
                db_entry.value = value
                db_entry.ttl = ttl
                db_entry.ttl_type = ttl_type
                db_entry.expire_at = expires_at
            else:
                session.add(entry)
            await session.commit()

    return key


async def cache_get(key: str, default: str | None = None) -> str | None:
    """Returns an entry from the cache else ``default`` if no entry exists."""
    async with async_session.begin() as session:
        if entry := await session.get(Cache, key):
            if _cache_is_live(entry):
                if entry.ttl_type == CACHE_TTL_TYPE_ROLLING:
                    entry.expire_at = _cache_calc_expires(entry.ttl)
                return entry.value

            await session.delete(entry)

    return default


async def cache_pop(key: str, default: str | None = None) -> str | None:
    """Returns an entry from the cache else ``default``.

    If the entry exists it will be removed from the cache.
    """
    async with async_session.begin() as session:
        if (entry := await session.get(Cache, key)) is None:
            return default

        value = entry.value if _cache_is_live(entry) else default
        await session.delete(entry)

    return value


def _cache_calc_expires(ttl: int) -> datetime.datetime:
    # we store without a timezone, so we produce a naive timestamp
    return datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl)  # noqa: DTZ003


def _cache_is_live(entry: Cache) -> bool:
    # we store without a timezone, so compare against a naive UTC now
    return entry.expire_at > datetime.datetime.utcnow()  # noqa: DTZ003


def _cache_guid(prefix: str | None = None) -> str:
    if prefix is None:
        prefix = ""
    return f"{prefix}{new_uuid()}"


async def _cache_purge_expired() -> None:
    """Removes all entries that are expired."""
    # we store without a timezone, so compare against a naive UTC now
    utc_now = datetime.datetime.utcnow()  # noqa: DTZ003
    stmt = sa.delete(Cache).where(Cache.expire_at <= utc_now)
    async with async_session.begin() as session:
        await session.execute(stmt)

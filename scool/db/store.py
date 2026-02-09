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
        return [schemas.Platform.model_validate(row) for row in result.scalars()]


async def platform(platform_id: str) -> schemas.Platform:
    stmt = sa.select(Platform).where(Platform.id == platform_id)
    async with async_session() as session:
        if result := await session.execute(stmt):
            return schemas.Platform.model_validate(result.scalar())
        raise LookupError(platform_id)


async def user(user_id: str) -> schemas.AuthUser:
    async with async_session() as session:
        result = await session.get(AuthUser, user_id)
        if not result:
            raise LookupError(user_id)
        return schemas.AuthUser.model_validate(result)


async def user_by_client_id(client_id: str) -> schemas.AuthUser:
    stmt = sa.select(AuthUser).where(
        sa.func.lower(AuthUser.client_id) == client_id.lower() and AuthUser.is_active
    )
    async with async_session() as session:
        if result := await session.execute(stmt):
            return schemas.AuthUser.model_validate(result.scalar())
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
        return [schemas.AuthJsonWebKey.model_validate(row) for row in result.scalars()]


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


async def cache_add(
    key: str,
    value: str,
    *,
    ttl: int = CACHE_TTL_DEFAULT,
    ttl_type: str = CACHE_TTL_TYPE_FIXED,
    append_guid: bool = False,
) -> str | None:
    """Adds an entry in the cache.

    Returns the key if the entry was added, else None if the entry already
    exists.
    """
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
            return None
        else:
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
    return datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl)  # noqa: DTZ003 # ty: ignore[deprecated]


def _cache_is_live(entry: Cache) -> bool:
    # we store without a timezone, so compare against a naive UTC now
    return entry.expire_at > datetime.datetime.utcnow()  # noqa: DTZ003 # ty: ignore[deprecated]


def _cache_guid(prefix: str | None = None) -> str:
    if prefix is None:
        prefix = ""
    return f"{prefix}{new_uuid()}"


async def _cache_purge_expired() -> None:
    """Removes all entries that are expired."""
    # we store without a timezone, so compare against a naive UTC now
    utc_now = datetime.datetime.utcnow()  # noqa: DTZ003 # ty: ignore[deprecated]
    stmt = sa.delete(Cache).where(Cache.expire_at <= utc_now)
    async with async_session.begin() as session:
        await session.execute(stmt)

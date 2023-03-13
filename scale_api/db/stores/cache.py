import datetime
import logging
from collections.abc import Callable, Mapping
from typing import TypeVar

import sqlalchemy as sa

from scale_api import aio

from .. import errors
from ..core import SessionLocal, new_uuid
from ..models import Cache

logger = logging.getLogger(__name__)

T = TypeVar("T")

NowFunc = Callable[..., datetime.datetime]


class CacheStore:
    """Cache Repository."""

    TTL_DEFAULT = 3600
    TTL_TYPE_FIXED = "fixed"
    TTL_TYPE_ROLLING = "rolling"

    def __init__(self, now_func: NowFunc = datetime.datetime.utcnow) -> None:
        self.now = now_func
        self.next_purge_time = now_func()

    def _calc_expires(self, ttl: int) -> datetime.datetime:
        return self.now() + datetime.timedelta(seconds=ttl)

    # noinspection PyMethodMayBeStatic
    def guid(self, prefix: str = "") -> str:
        return f"{prefix}{new_uuid()}"

    def add(
        self,
        key: str,
        value: str,
        *,
        ttl: int = TTL_DEFAULT,
        ttl_type: str = TTL_TYPE_FIXED,
        append_guid: bool = False,
    ) -> str:
        """Adds an entry to the cache else raises if the entry already exists."""
        key = self.guid(key) if append_guid else key
        self.add_many({key: value}, ttl=ttl, ttl_type=ttl_type)
        return key

    def add_many(
        self,
        data: Mapping[str, str],
        *,
        ttl: int = TTL_DEFAULT,
        ttl_type: str = TTL_TYPE_FIXED,
    ) -> None:
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
            logger.warning("Cache.add_many failed, trying purge: %r", exc)
            self.purge_expired()
            # Retry after purging cache
            with SessionLocal() as session:
                session.add_all(entries)
                session.commit()

    def put(
        self,
        key: str,
        value: str,
        *,
        ttl: int = TTL_DEFAULT,
        ttl_type: str = TTL_TYPE_FIXED,
        append_guid: bool = False,
    ) -> str:
        """Updates an entry in the cache else creates a new entry."""
        key = self.guid(key) if append_guid else key
        self.put_many({key: value}, ttl=ttl, ttl_type=ttl_type)
        return key

    def put_many(
        self,
        data: Mapping[str, str],
        *,
        ttl: int = TTL_DEFAULT,
        ttl_type: str = TTL_TYPE_FIXED,
    ) -> None:
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
            except errors.IntegrityError:
                session.rollback()
                # Do a purge, so we don't try to update expired entries
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

    def get(self, key: str, default: T | None = None) -> str | T:
        """Returns an entry from the cache else ``default`` if no entry exists."""
        with SessionLocal() as session:
            entry = session.get(Cache, key)
            if entry:
                if entry.expire_at is None:
                    return entry.value  # type: ignore[return-value]

                if entry.expire_at > self.now():
                    if entry.ttl_type == "rolling":
                        entry.expire_at = self._calc_expires(entry.ttl)
                        session.commit()
                    return entry.value  # type: ignore[return-value]

                session.delete(entry)
                session.commit()

        return default  # type: ignore[return-value]

    def get_many(self, key_prefix: str) -> Mapping[str, str]:
        """Returns entries from the cache.

        The entries are returned in a dict where they key is the cache key
        and the value is cache value.
        """
        now = self.now()
        stmt = sa.select(Cache).where(Cache.key.ilike(key_prefix + "%"))
        with SessionLocal.begin() as session:
            entries = {}
            for entry in session.execute(stmt).scalars():
                if entry.expire_at is None or entry.expire_at > now:
                    entries[entry.key] = entry.value
                    if entry.ttl_type == "rolling":
                        entry.expire_at = self._calc_expires(entry.ttl)
                else:
                    session.delete(entry)
        return entries  # type: ignore[return-value]

    def pop(self, key: str, default: T | None = None) -> str | T | None:
        """Returns an entry from the cache else ``default``.

        If the entry exists it will be removed from the cache.
        """
        with SessionLocal.begin() as session:
            entry = session.get(Cache, key)
            if entry is None:
                value = default
            elif entry.expire_at is None or entry.expire_at > self.now():
                value = entry.value
            else:
                value = default
            session.delete(entry)
        return value

    def purge_expired(self) -> int:
        """Removes all entries that are expired."""
        stmt = sa.delete(Cache).where(Cache.expire_at <= self.now())
        with SessionLocal.begin() as session:
            return session.execute(stmt).rowcount  # type: ignore

    def purge_expired_safe(self) -> None:
        if self.now() < self.next_purge_time:
            return
        self.next_purge_time = self.now() + datetime.timedelta(seconds=self.TTL_DEFAULT)
        try:
            purge_count = self.purge_expired()
            logger.info("Cache.purge_expired count %s", purge_count)
        except Exception as exc:
            logger.warning("Cache.purge_expired failed: %r", exc)

    add_async = aio.wrap(add)
    add_many_async = aio.wrap(add_many)
    put_async = aio.wrap(put)
    put_many_async = aio.wrap(put_many)
    get_async = aio.wrap(get)
    get_many_async = aio.wrap(get_many)
    pop_async = aio.wrap(pop)
    purge_expired_async = aio.wrap(purge_expired)

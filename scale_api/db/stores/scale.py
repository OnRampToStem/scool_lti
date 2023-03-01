import logging

import sqlalchemy as sa

from scale_api import aio, schemas
from ..core import SessionLocal
from ..models import AuthJsonWeKey, AuthUser, Platform

logger = logging.getLogger(__name__)


class ScaleStore:
    """SCALE Application Repository."""

    # noinspection PyMethodMayBeStatic
    def platforms(self) -> list[schemas.Platform]:
        stmt = sa.select(Platform)
        with SessionLocal() as session:
            result = session.execute(stmt)
            platforms = [
                schemas.Platform.from_orm(row)
                for row in result.scalars()
            ]

        return platforms

    # noinspection PyMethodMayBeStatic
    def platform(self, platform_id: str) -> schemas.Platform:
        stmt = sa.select(Platform).where(Platform.id == platform_id)
        with SessionLocal() as session:
            result = session.execute(stmt).scalar()
            if not result:
                raise LookupError(platform_id)
            platform = schemas.Platform.from_orm(result)

        return platform

    # noinspection PyMethodMayBeStatic
    def user(self, user_id: str) -> schemas.AuthUser:
        with SessionLocal() as session:
            result = session.get(AuthUser, user_id)
            if not result:
                raise LookupError(user_id)
            user = schemas.AuthUser.from_orm(result)

        return user

    # noinspection PyMethodMayBeStatic
    def user_by_client_id(self, client_id: str) -> schemas.AuthUser:
        stmt = sa.select(AuthUser).where(
            sa.func.lower(AuthUser.client_id) == client_id.lower()
            and AuthUser.is_active
        )
        with SessionLocal() as session:
            result = session.execute(stmt).scalar()
            if not result:
                raise LookupError(client_id)
            user = schemas.AuthUser.from_orm(result)

        return user

    # noinspection PyMethodMayBeStatic
    def json_web_keys(self) -> list[schemas.AuthJsonWebKey]:
        stmt = sa.select(AuthJsonWeKey).where(
            AuthJsonWeKey.valid_from <= sa.func.now(),
            sa.or_(
                AuthJsonWeKey.valid_to == None,  # noqa comparison op
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

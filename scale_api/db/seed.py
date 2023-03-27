"""
SCALE database seeder

Used to seed a newly created SCALE database with data.
"""
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, cast

from .. import keys, security, settings
from . import store
from .core import async_session, engine
from .models import (
    AuthJsonWeKey,
    AuthUser,
    Base,
    Platform,
)

logger = logging.getLogger(__name__)

SeedData = dict[str, Any]


async def init_platforms(data: SeedData) -> None:
    platforms = store.platforms()
    if platforms:
        logger.info("Platforms exist, skipping")
        return
    async with async_session.begin() as session:
        for platform in data["platforms"]:
            new_plat = Platform(**platform)
            session.add(new_plat)


async def init_auth_users(data: SeedData) -> None:
    try:
        async with async_session.begin() as session:
            for user in data["auth_users"]:
                secret = user.pop("client_secret")
                user["client_secret_hash"] = security.hash_password(secret)
                new_user = AuthUser(**user)
                session.add(new_user)
    except Exception as exc:
        logger.info("AuthUsers update failed: %r", exc)


async def init_auth_json_web_keys(_: SeedData) -> None:
    web_keys = await store.json_web_keys()
    if web_keys:
        logger.info("AuthJsonWebKeys exist, skipping")
        return
    async with async_session.begin() as session:
        web_key = keys.generate_private_key()
        jwk = AuthJsonWeKey(
            kid=web_key.kid,
            data=web_key.data.get_secret_value(),
        )
        session.add(jwk)


async def init_db(data: SeedData) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await init_platforms(data)
    await init_auth_users(data)
    await init_auth_json_web_keys(data)


async def run(seed_file: Path) -> None:
    logger.info("Using DB Engine: %s", engine)
    logger.info("Using seed file: %s", seed_file)
    with seed_file.open(mode="r", encoding="utf-8") as f:
        data = json.load(f)
    await init_db(cast(SeedData, data))


async def async_main() -> None:
    if settings.api.is_production:
        raise RuntimeError("INVALID_ENV", settings.api.env)

    seed_file = Path(sys.argv[1]) if len(sys.argv) > 1 else settings.db.seed_file
    if seed_file:
        await run(seed_file)
    else:
        logger.warning("No seed file provided, use SCALE_API_DB_SEED_FILE to set")


if __name__ == "__main__":
    asyncio.run(async_main())

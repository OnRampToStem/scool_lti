"""
FastAPI main entry point

This modules configures our FastAPI application.
"""
import asyncio
import contextlib
import logging
from typing import Any

from fastapi import FastAPI

from . import __version__, aio, db, settings
from .routes import api_router

logger = logging.getLogger(__name__)

logger.info("Using Environment [%s]", settings.api.env)

logger.info("Is Production: %s", settings.api.is_production)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> Any:
    logger.info("Running in loop [%r]", asyncio.get_running_loop())
    try:
        yield {
            "http_client": aio.http_client,
        }
    finally:
        logger.info("closing db engine connections")
        await db.engine.dispose()
        logger.info("closing httpx client")
        await aio.http_client.aclose()


app = FastAPI(
    title="OR2STEM API",
    version=__version__,
    lifespan=lifespan,
    docs_url=f"{settings.api.path_prefix}/docs",
    redoc_url=None,
    openapi_url=f"{settings.api.path_prefix}/openapi.json",
    debug=settings.api.debug_app,
)

app.include_router(api_router, prefix=settings.api.path_prefix)

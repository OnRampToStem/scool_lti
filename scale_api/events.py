import asyncio
import concurrent.futures
import contextlib
import logging
from typing import Any, TypedDict

import httpx
from fastapi import FastAPI

from . import aio, db
from .settings import app_config

logger = logging.getLogger(__name__)


class State(TypedDict):
    executor: concurrent.futures.Executor
    http_client: httpx.AsyncClient


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> Any:
    loop = asyncio.get_running_loop()
    logger.info("Running in loop [%r]", loop)
    workers = app_config.api.thread_pool_workers
    logger.info("ThreadPoolExecutor(max_workers=%s)", workers)
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="scale_api",
    )
    loop.set_default_executor(executor)
    try:
        yield {
            "executor": executor,
            "http_client": aio.http_client,
        }
    finally:
        logger.info("Shutdown event")
        await db.engine.dispose()
        await aio.http_client.aclose()

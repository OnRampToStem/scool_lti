"""
FastAPI main entry point

This modules configures our FastAPI application.
"""
import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import fastapi
import shortuuid

from . import __version__, aio, db, routes, settings

logger = logging.getLogger(__name__)

logger.info("Using Environment [%s]", settings.api.env)

logger.info("Is Production: %s", settings.api.is_production)


@contextlib.asynccontextmanager
async def lifespan(_: fastapi.FastAPI) -> Any:
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


app = fastapi.FastAPI(
    title="OR2STEM API",
    version=__version__,
    lifespan=lifespan,
    docs_url=f"{settings.api.path_prefix}/docs",
    redoc_url=None,
    openapi_url=f"{settings.api.path_prefix}/openapi.json",
    debug=settings.api.debug_app,
)


@app.middleware("http")
async def logging_middleware(
    request: fastapi.Request,
    call_next: Callable[[fastapi.Request], Awaitable[fastapi.Response]],
) -> fastapi.Response:
    if request.url.path == request.app.url_path_for("health_check"):
        return await call_next(request)
    if not (request_id := request.headers.get("x-request-id")):
        request_id = shortuuid.uuid()
    request.state.request_id = request_id
    settings.ctx_request_id.set(request_id)
    client_ip = request.client.host if request.client else ""
    path = request.url.path
    if query := request.url.query:
        path += f"?{query}"
    logger.info(
        'start: %s - %s %s HTTP/%s - %s - "%s"',
        client_ip,
        request.method,
        path,
        request["http_version"],
        request.headers.get("referer"),
        request.headers.get("user-agent"),
    )
    tick_start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        tick_end = time.perf_counter()
        logger.info("end: %s [%r] - %s", 500, exc, round(tick_end - tick_start, 6))
        raise exc from None
    else:
        tick_end = time.perf_counter()
        logger.info(
            "end: %s - %s", response.status_code, round(tick_end - tick_start, 6)
        )
        return response


app.include_router(routes.router, prefix=settings.api.path_prefix)

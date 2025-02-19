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

from . import __version__, db, routes, services, settings

logger = logging.getLogger(__name__)

logger.info(
    "Environment [%s], Is Production: %s", settings.ENV, settings.is_production()
)


@contextlib.asynccontextmanager
async def lifespan(_: fastapi.FastAPI) -> Any:
    logger.info("Running in loop [%r]", asyncio.get_running_loop())
    try:
        async with services.http_client:
            yield
    finally:
        logger.info("closing db engine connections")
        await db.engine.dispose()


app = fastapi.FastAPI(
    title="SCOOL LTI",
    version=__version__,
    lifespan=lifespan,
    docs_url=f"{settings.PATH_PREFIX}/docs",
    redoc_url=None,
    openapi_url=f"{settings.PATH_PREFIX}/openapi.json",
    debug=settings.DEBUG,
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
    client_ip = request.client.host if request.client else "0.0.0.0"  # noqa:S104
    settings.CTX_REQUEST.set(
        settings.RequestContext(request_id=request_id, client_ip=client_ip)
    )
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
        raise
    else:
        tick_end = time.perf_counter()
        logger.info(
            "end: %s - %s", response.status_code, round(tick_end - tick_start, 6)
        )
        return response


app.include_router(routes.router, prefix=settings.PATH_PREFIX)

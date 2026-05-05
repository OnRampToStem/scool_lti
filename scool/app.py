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

This module configures our FastAPI application.
"""

import asyncio
import contextlib
import logging
from typing import Any

import authstar
import fastapi
from starlette.middleware import Middleware

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


middleware = [
    Middleware(
        authstar.ContextMiddleware,
        context_class=settings.RequestContext,
    ),
    Middleware(
        authstar.LogMiddleware,
        logger_name="scool",
        excluded_paths=["/lb-status", "/api/lb-status"],
    ),
]

app = fastapi.FastAPI(
    debug=settings.DEBUG,
    title="SCOOL LTI",
    version=__version__,
    lifespan=lifespan,
    middleware=middleware,
    docs_url=f"{settings.PATH_PREFIX}/docs",
    redoc_url=None,
    openapi_url=f"{settings.PATH_PREFIX}/openapi.json",
)

app.include_router(routes.router, prefix=settings.PATH_PREFIX)

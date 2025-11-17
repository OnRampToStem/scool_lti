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
FastAPI Middleware
"""

import logging
import time

import shortuuid
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from . import settings

logger = logging.getLogger(__name__)


class ContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not (request_id := request.headers.get("x-request-id")):
            request_id = shortuuid.uuid()
        settings.CTX_REQUEST.set(
            settings.RequestContext(
                request_id=request_id,
                client_ip=request.client.host if request.client else None,
            )
        )
        return await call_next(request)


class LogMiddleware(BaseHTTPMiddleware):
    async def log(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path == request.app.url_path_for("health_check"):
            return await call_next(request)
        path = request.url.path
        if query := request.url.query:
            path += f"?{query}"
        logger.info(
            'start: %s - %s %s HTTP/%s - %s - "%s"',
            request.client.host if request.client else None,
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

    # create an alias so we show a descriptive function name when logging
    dispatch = log


handlers = [
    Middleware(ContextMiddleware),  # ty: ignore[invalid-argument-type]
    Middleware(LogMiddleware),  # ty: ignore[invalid-argument-type]
]

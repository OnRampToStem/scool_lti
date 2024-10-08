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
ASGI Server entrypoint

This module will launch the application. To run in a local development
environment it can be run without any arguments:

    python3 -m <main_package>

By default, dev mode starts up on port 8443.

To run in production mode, pass `prod` as the sole argument:

    python -m <main_package> prod
"""

import logging
import os
import sys

import trustme
import uvicorn

from . import settings

logger = logging.getLogger(__name__)


def start() -> None:
    if not (cpu_count := os.cpu_count()):
        cpu_count = 1

    app = f"{__package__}.app:app"
    host = "0.0.0.0"  # noqa:S104
    port = settings.PORT
    reload = False
    workers = max(2, min(cpu_count, 4))
    log_level = settings.LOG_LEVEL_UVICORN.lower()
    access_log = False
    proxy_headers = True
    forwarded_allow_ips = settings.FORWARDED_ALLOW_CIDRS
    server_header = False

    if len(sys.argv) < 2 or sys.argv[1] != "prod":  # noqa:PLR2004
        logger.warning("Running in dev mode")
        host = "127.0.0.1"
        reload = True
        workers = 1

    logger.info(locals())

    ssl_ca = trustme.CA()

    with (
        ssl_ca.cert_pem.tempfile() as ssl_certfile,
        ssl_ca.private_key_pem.tempfile() as ssl_keyfile,
    ):
        uvicorn.run(
            app=app,
            host=host,
            port=port,
            reload=reload,
            workers=workers,
            log_level=log_level,
            access_log=access_log,
            proxy_headers=proxy_headers,
            forwarded_allow_ips=forwarded_allow_ips,
            server_header=server_header,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
        )

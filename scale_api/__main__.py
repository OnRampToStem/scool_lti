"""
Main entrypoint

This script will launch the application. To run in a local development
environment it can be run with any arguments:

    python3 -m <main_package>

By default, dev mode starts up on port 8443.

To run in production mode, pass `prod` as the sole argument:

    python -m <main_package> prod
"""
import logging
import os
import sys
from pathlib import Path

import uvicorn

from scale_api import settings

MAIN_PACKAGE = Path(__file__).parent.name

logger = logging.getLogger(f"{MAIN_PACKAGE}.main")


def main() -> None:
    if not (cpu_count := os.cpu_count()):
        cpu_count = 1
    app = f"{MAIN_PACKAGE}.app:app"
    host = "0.0.0.0"  # noqa:S104
    port = settings.api.port
    reload = False
    workers = max(2, min(cpu_count, 4))
    log_level = settings.log.level_uvicorn.lower()
    access_log = False
    proxy_headers = True
    server_header = False
    forwarded_allow_ips = "*"
    ssl_keyfile = None
    ssl_certfile = None

    if len(sys.argv) < 2 or sys.argv[1] != "prod":  # noqa:PLR2004
        logger.warning("Running in dev mode")
        host = "127.0.0.1"
        reload = True
        workers = 1
        if settings.api.use_ssl_for_app_run_local:
            port = 443
            ssl_keyfile = str(settings.BASE_PATH / "tests/certs/local_ssl_key.pem")
            ssl_certfile = str(settings.BASE_PATH / "tests/certs/local_ssl_cert.pem")

    logger.info(locals())
    uvicorn.run(
        app=app,
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level=log_level,
        access_log=access_log,
        proxy_headers=proxy_headers,
        server_header=server_header,
        forwarded_allow_ips=forwarded_allow_ips,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
    )


if __name__ == "__main__":
    main()

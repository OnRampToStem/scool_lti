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


class EndpointLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "lb-status" not in record.getMessage()


def main() -> None:
    config = uvicorn.Config(app=f"{MAIN_PACKAGE}.app:app")
    config.port = settings.api.port
    config.server_header = False
    config.forwarded_allow_ips = "*"
    config.proxy_headers = True
    config.log_level = settings.log.level_uvicorn.lower()

    # do not log health checks
    logging.getLogger("uvicorn.access").addFilter(EndpointLogFilter())

    if len(sys.argv) > 1 and sys.argv[1] == "prod":
        config.host = "0.0.0.0"  # noqa: S104
        cpu_count = os.cpu_count() or 1
        config.workers = max(2, min(4, cpu_count * 2))
        server = uvicorn.Server(config=config)
        logger.warning("running in prod mode: Config(%s)", config.__dict__)
        server.run()
    else:
        config.reload = True
        if settings.api.use_ssl_for_app_run_local:
            cert_path = Path(__file__).parent.parent / "tests/certs"
            config.port = 443
            config.ssl_keyfile = f"{cert_path / 'local_ssl_key.pem'}"
            config.ssl_certfile = f"{cert_path / 'local_ssl_cert.pem'}"

        logger.warning("running in dev mode: Config(%s)", config.__dict__)

        # must use `run` for reloading to work
        uvicorn.run(
            app=config.app,
            reload=config.reload,
            port=config.port,
            ssl_keyfile=config.ssl_keyfile,
            ssl_certfile=config.ssl_certfile,
            server_header=config.server_header,
            forwarded_allow_ips=config.forwarded_allow_ips,
            proxy_headers=config.proxy_headers,
            log_level=config.log_level,
        )


if __name__ == "__main__":
    main()

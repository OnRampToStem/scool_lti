"""
FastAPI main entry point

This modules configures our FastAPI application.
"""
import logging
import sys

from fastapi import FastAPI, Request
from fastapi import __version__ as fastapi_version
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

# noinspection PyPackageRequirements
from starlette.middleware.sessions import SessionMiddleware

from scale_api import (
    __version__,
    app_config,
    db,
    events,
)
from scale_api.routes import api_router, index_api

logger = logging.getLogger(__name__)

logger.info(
    "Using Environment [%s] file for settings: %s",
    app_config.ENV,
    app_config.Config.env_file,
)

logger.info("Is Production: %s", app_config.is_production)

app = FastAPI(
    title="OR2STEM API",
    version=__version__,
    lifespan=events.lifespan,
    docs_url=f"{app_config.PATH_PREFIX}/docs",
    redoc_url=None,
    openapi_url=f"{app_config.PATH_PREFIX}/openapi.json",
    debug=app_config.DEBUG_APP,
)

logger.info("Adding GZip middleware")
app.add_middleware(GZipMiddleware)

logger.info(
    "Adding Session middleware with max age (in secs): %s", app_config.SESSION_MAX_AGE
)
# Session middleware allows use of ``request.session`` as a dict and is used
# to store SCALE user info. The session cookie is a JWT, so information
# stored is not encrypted (just signed).
app.add_middleware(
    SessionMiddleware,
    secret_key=app_config.SECRET_KEY,
    max_age=app_config.SESSION_MAX_AGE,
    https_only=True,
)

logger.info("Adding CORS middleware for origins: %s", app_config.BACKEND_CORS_ORIGINS)
# CORS middleware allows for making xhr requests to the API from the
# front-end webapp. This is used mainly for development so that the front-end
# can be run on ``http://localhost:8080`` and able to make calls to the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(u) for u in app_config.BACKEND_CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
@app.get(app_config.PATH_PREFIX, include_in_schema=False)
async def index(request: Request):  # type: ignore[no-untyped-def]
    return await index_api(request)


@app.get(f"{app_config.PATH_PREFIX}/lb-status", include_in_schema=False)
async def health_check():  # type: ignore[no-untyped-def]
    """Provides a health check endpoint for the Load Balancer."""
    return {
        "app_version": __version__,
        "framework_version": fastapi_version,
        "lang_version": sys.version,
        "environment": app_config.ENV,
        "engine": str(db.engine),
    }


# All routes are defined in ``scale_api.routes``
app.include_router(api_router, prefix=app_config.PATH_PREFIX)


def main() -> None:
    """Runs app in a local development mode.

    Only use for local development testing.
    """
    from pathlib import Path

    import uvicorn

    run_opts: dict[str, int | bool | str] = {
        "port": 8000,
        "reload": True,
    }

    if app_config.USE_SSL_FOR_APP_RUN_LOCAL:
        cert_path = Path(__file__).parent.parent / "tests/certs"
        run_opts["port"] = 443
        run_opts["ssl_keyfile"] = f"{cert_path / 'local_ssl_key.pem'}"
        run_opts["ssl_certfile"] = f"{cert_path / 'local_ssl_cert.pem'}"

    events.on_startup_main()
    uvicorn.run(
        "scale_api.app:app",
        **run_opts,  # type: ignore[arg-type]
    )
    events.on_shutdown_main()


if __name__ == "__main__":
    main()

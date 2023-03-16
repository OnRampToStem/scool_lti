"""
FastAPI main entry point

This modules configures our FastAPI application.
"""
import logging

from fastapi import FastAPI

from . import __version__, events
from .routes import api_router
from .settings import app_config

logger = logging.getLogger(__name__)

logger.info(
    "Using Environment [%s] file for settings: %s",
    app_config.api.env,
    app_config.api.Config.env_file,
)

logger.info("Is Production: %s", app_config.api.is_production)

app = FastAPI(
    title="OR2STEM API",
    version=__version__,
    lifespan=events.lifespan,
    docs_url=f"{app_config.api.path_prefix}/docs",
    redoc_url=None,
    openapi_url=f"{app_config.api.path_prefix}/openapi.json",
    debug=app_config.api.debug_app,
)

# All routes are defined in ``scale_api.routes``
app.include_router(api_router, prefix=app_config.api.path_prefix)

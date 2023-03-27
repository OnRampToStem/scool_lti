"""
FastAPI main entry point

This modules configures our FastAPI application.
"""
import logging

from fastapi import FastAPI

from . import __version__, events, settings
from .routes import api_router

logger = logging.getLogger(__name__)

logger.info(
    "Using Environment [%s] file for settings: %s",
    settings.api.env,
    settings.api.Config.env_file,
)

logger.info("Is Production: %s", settings.api.is_production)

app = FastAPI(
    title="OR2STEM API",
    version=__version__,
    lifespan=events.lifespan,
    docs_url=f"{settings.api.path_prefix}/docs",
    redoc_url=None,
    openapi_url=f"{settings.api.path_prefix}/openapi.json",
    debug=settings.api.debug_app,
)

# All routes are defined in ``scale_api.routes``
app.include_router(api_router, prefix=settings.api.path_prefix)

"""
API Endpoints

Contains the configuration for all API endpoint routers.
"""
from fastapi import APIRouter

from . import auth, core, lti_v13, well_known

api_router = APIRouter()

api_router.include_router(
    core.router,
    prefix="",
    tags=["Core"],
)

api_router.include_router(
    auth.router,
    prefix="/v1/auth",
    tags=["Authentication"],
)

api_router.include_router(
    well_known.router,
    prefix="/.well-known",
    tags=["Well Known"],
)

api_router.include_router(
    lti_v13.router,
    prefix="/lti/v1.3",
    tags=["LTI 1.3"],
)

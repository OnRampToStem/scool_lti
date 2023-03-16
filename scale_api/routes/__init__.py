"""
API Endpoints

Contains the configuration for all API endpoint routers.
"""
from fastapi import APIRouter

from .auth import router as router_auth
from .core import router as router_core
from .lti_v13 import router as router_lti
from .well_known import router as router_well_known

api_router = APIRouter()

api_router.include_router(
    router_core,
    prefix="",
    tags=["Core"],
)

api_router.include_router(
    router_auth,
    prefix="/v1/auth",
    tags=["Authentication"],
)

api_router.include_router(
    router_well_known,
    prefix="/.well-known",
    tags=["Well Known"],
)

api_router.include_router(
    router_lti,
    prefix="/lti/v1.3",
    tags=["LTI 1.3"],
)

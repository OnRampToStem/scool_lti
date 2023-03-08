"""
API Endpoints

Contains the configuration for all API endpoint routers.
"""
from fastapi import APIRouter, Security

from ..auth import authorize
from ..lti.routes import router as router_lti
from .auth import index_api as index_api
from .auth import router as router_auth
from .files import router as router_files
from .firebase import router as router_firebase
from .messages import router as router_messages
from .platforms import router as router_platforms
from .users import router as router_users
from .well_known import router as router_well_known

api_router = APIRouter()

api_router.include_router(
    router_lti,
    prefix="/lti/v1.3",
    tags=["LTI 1.3"],
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

# Secured routes from this point on
api_router.include_router(
    router_platforms,
    prefix="/v1/platforms",
    tags=["Platforms"],
    dependencies=[Security(authorize, scopes=["plat"])],
)

api_router.include_router(
    router_users,
    prefix="/v1/users",
    tags=["Users"],
    dependencies=[Security(authorize)],
)

api_router.include_router(
    router_firebase,
    prefix="/v1/FirebaseCompat",
    tags=["Firebase Compatibility"],
    dependencies=[Security(authorize)],
)

api_router.include_router(
    router_messages,
    prefix="/v1/messages",
    tags=["Messages"],
    dependencies=[Security(authorize)],
)

api_router.include_router(
    router_files,
    prefix="/v1/files",
    tags=["Files"],
    dependencies=[Security(authorize)],
)

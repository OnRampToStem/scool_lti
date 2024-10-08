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
OAuth/OIDC Well Known routes
"""

from typing import Any

from async_lru import alru_cache
from fastapi import APIRouter, Request

from .. import keys, settings

router = APIRouter()


@router.get("/jwks.json")
async def jwks() -> dict[str, Any]:
    """JSON Web Key Set endpoint."""
    return await _load_jwks()


@router.get("/oauth-authorization-server")
async def oauth_server_metadata(request: Request) -> dict[str, Any]:
    """OAuth 2.0 configuration endpoint."""
    return {
        "issuer": settings.JWT_ISSUER,
        "token_endpoint": str(request.url_for("oauth_token")),
        "response_types_supported": "token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "private_key_jwt",
        ],
        "jwks_uri": str(request.url_for("jwks")),
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ],
    }


@alru_cache(ttl=86400)
async def _load_jwks() -> dict[str, Any]:
    ks = await keys.public_key_set()
    ks_dict = ks.as_dict()
    for entry in ks_dict["keys"]:
        if "use" not in entry:
            entry["use"] = "sig"
        if "alg" not in entry:
            entry["alg"] = "RS256"
    return ks_dict  # type: ignore[return-value]

"""
OAuth/OIDC Well Known routes
"""
from typing import Any

from fastapi import APIRouter, Request

from .. import keys, settings

router = APIRouter()


@router.get("/jwks.json")
async def jwks() -> dict[str, Any]:
    """JSON Web Key Set endpoint."""
    ks = await keys.public_key_set()
    ks_dict = ks.as_dict()
    for entry in ks_dict["keys"]:
        if "use" not in entry:
            entry["use"] = "sig"
        if "alg" not in entry:
            entry["alg"] = "RS256"
    return ks_dict  # type: ignore[return-value]


@router.get("/oauth-authorization-server")
async def oauth_server_metadata(request: Request) -> dict[str, Any]:
    """OAuth 2.0 configuration endpoint."""
    return {
        "issuer": settings.api.jwt_issuer,
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

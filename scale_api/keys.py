"""
JSON Web Keys
"""
import datetime
import logging
from typing import List

from authlib import jose

from . import (
    aio,
    db,
    schemas,
)

logger = logging.getLogger(__name__)


# TODO: cache with a fixed ttl or using cache headers from response
async def get_jwks_from_url(url: str) -> jose.KeySet:
    """Returns a JWKS from the given URL."""
    logger.info('Fetching JWKS from %s', url)
    r = await aio.http_client.get(url, timeout=5.0)
    r.raise_for_status()
    jwks_json = r.json()
    try:
        return jose.JsonWebKey.import_key_set(jwks_json)
    except Exception:
        logger.error('Failed to import key set: %s', jwks_json)
        raise


async def private_keys() -> List:
    """Returns a list of private ``AuthJsonWebKeys`` from the database."""
    web_keys = await db.store.json_web_keys_async()
    now = datetime.datetime.utcnow()
    return [
        k
        for k in web_keys
        if k.valid_from < now < k.valid_to
    ]


async def json_web_private_keys() -> List:
    web_keys = await private_keys()
    return [
        jose.JsonWebKey.import_key(k.data.get_secret_value())
        for k in web_keys
    ]


async def private_key() -> jose.RSAKey:
    """Returns the default JSON Web Key from the database.

    If more than one key is stored then the key that has the greater
    ``valid_to`` date is provided.
    """
    web_keys = await private_keys()
    main_key = None
    for key in web_keys:
        if main_key is None:
            main_key = key
        elif key.valid_to > main_key.valid_to:
            main_key = key

    if main_key is None:
        raise RuntimeError('No valid JWKS found')

    return jose.JsonWebKey.import_key(main_key.data.get_secret_value())


# TODO: cache to speed up our ``/jwks.json`` endpoint
async def public_keys() -> List:
    """Returns a list of public JSON Web Keys."""
    privates = await json_web_private_keys()
    return [
        jose.JsonWebKey.import_key(pk.as_pem(is_private=False))
        for pk in privates
    ]


async def public_keyset() -> jose.KeySet:
    """Returns a public JSON Web Keyset."""
    publics = await public_keys()
    return jose.KeySet(publics)


def generate_private_key() -> schemas.AuthJsonWebKey:
    """Returns a newly generated private JSON Web Key"""
    private_key = jose.JsonWebKey.generate_key(
        kty='RSA',
        crv_or_size=2048,
        is_private=True
    )
    kid = private_key.as_dict(add_kid=True)['kid']
    data = private_key.as_pem(is_private=True)
    return schemas.AuthJsonWebKey(
        kid=kid,
        data=data,
        valid_from=datetime.datetime.utcnow()
    )

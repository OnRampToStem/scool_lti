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


# TODO: cache results from this
async def get_jwks_from_url(url: str) -> jose.KeySet:
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
    web_keys = db.store.json_web_keys()
    return [
        jose.JsonWebKey.import_key(k.data.get_secret_value())
        for k in web_keys
    ]


async def private_key() -> jose.RSAKey:
    web_keys = db.store.json_web_keys()
    main_key = web_keys[0]
    if len(web_keys) > 1:
        for other_key in web_keys[1:]:
            if other_key.valid_from >= datetime.datetime.utcnow() and \
                    other_key.valid_to > main_key.valid_to:
                main_key = other_key

    return jose.JsonWebKey.import_key(main_key.data.get_secret_value())


# TODO: cache these too
async def public_keys() -> List:
    privates = await private_keys()
    return [
        jose.JsonWebKey.import_key(pk.as_pem(is_private=False))
        for pk in privates
    ]


async def public_keyset() -> jose.KeySet:
    publics = await public_keys()
    return jose.KeySet(publics)


def generate_private_key() -> schemas.AuthJsonWebKey:
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

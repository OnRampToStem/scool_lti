"""
JSON Web Keys
"""
import datetime
import logging
import time

import joserfc.jwk

from . import aio, db, schemas

logger = logging.getLogger(__name__)


class CachedKeySet:
    def __init__(
        self,
        key_set: joserfc.jwk.KeySet,
        expire_in: float | None = None,
    ) -> None:
        self.key_set = key_set
        if expire_in is None:
            self.expires_at = time.time() + 864000  # 24 hours
        else:
            self.expires_at = time.time() + expire_in

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= time.time()


_jwks_cache: dict[str, CachedKeySet] = {}


async def get_jwks_from_url(url: str, use_cache: bool = True) -> joserfc.jwk.KeySet:
    """Returns a JWKS from the given URL."""
    if use_cache:
        if cks := _jwks_cache.get(url):
            if not cks.is_expired:
                logger.info("Returning cached JWKS for %s", url)
                return cks.key_set
            logger.info("Cached JWKS for %s has expired", url)
        else:
            logger.info("Cached JWKS not found for %s", url)

    logger.info("Fetching JWKS from %s", url)
    r = await aio.http_client.get(url, timeout=5.0)
    logger.debug("JWKS headers: %r", r.headers)
    jwks_json = r.raise_for_status().json()
    try:
        ks = joserfc.jwk.KeySet.import_key_set(jwks_json)
    except Exception:
        logger.exception("Failed to import key set: %s", jwks_json)
        raise
    else:
        # TODO: check headers to see if there is a ttl use for `expire_in`
        #   cache-control': 'max-age=864000, private
        _jwks_cache[url] = CachedKeySet(ks)
        return ks


async def private_keys() -> list[schemas.AuthJsonWebKey]:
    """Returns a list of private ``AuthJsonWebKeys`` from the database."""
    web_keys = await db.store.json_web_keys()
    return [k for k in web_keys if k.is_valid]


async def json_web_private_keys() -> list[joserfc.jwk.RSAKey]:
    web_keys = await private_keys()
    return [joserfc.jwk.RSAKey.import_key(k.data.get_secret_value()) for k in web_keys]


async def private_key() -> joserfc.jwk.RSAKey:
    """Returns the default JSON Web Key from the database.

    If more than one key is stored then the key that has the greater
    ``valid_to`` date is provided.
    """
    if not (web_keys := await private_keys()):
        raise RuntimeError("JWKS_NOT_FOUND")

    main_key = web_keys[0]
    # Given more than one key, return the key that is valid furthest
    # in the future. No valid_to implies no end date. If both keys being
    # compared have no valid_to, then we select the newest key based on
    # valid_from.
    for key in web_keys[1:]:
        if key.valid_to is not None and main_key.valid_to is not None:
            if key.valid_to > main_key.valid_to:
                main_key = key
        elif key.valid_to is None and main_key.valid_to is None:
            if key.valid_from > main_key.valid_from:
                main_key = key
        elif key.valid_to is None:
            main_key = key

    if main_key is None:
        raise RuntimeError("VALID_JWKS_NOT_FOUND")

    return joserfc.jwk.RSAKey.import_key(main_key.data.get_secret_value())


async def public_keys() -> list[joserfc.jwk.RSAKey]:
    """Returns a list of public JSON Web Keys."""
    privates = await json_web_private_keys()
    return [joserfc.jwk.RSAKey.import_key(pk.as_pem(private=False)) for pk in privates]


async def public_key_set() -> joserfc.jwk.KeySet:
    """Returns a public JSON Web Key Set."""
    pub_keys = await public_keys()
    return joserfc.jwk.KeySet(pub_keys)  # type: ignore[arg-type]


def generate_private_key() -> schemas.AuthJsonWebKey:
    """Returns a newly generated private JSON Web Key"""
    pkey = joserfc.jwk.RSAKey.generate_key(key_size=2048, private=True)
    data = pkey.as_pem(private=True)
    if pkey.kid is None:
        raise ValueError
    return schemas.AuthJsonWebKey(
        kid=pkey.kid,
        data=schemas.make_secret(data.decode("ascii")),
        valid_to=None,
        valid_from=datetime.datetime.now(tz=datetime.UTC),
    )

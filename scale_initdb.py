"""
SCALE database init script.

Used to seed a newly created SCALE database with data. By default, the
script will look for the following file in the same directory:

    scale_initdb.json

See the provided `./scale_initdb-example.json` file for the required format.
"""
import json
import sys
from pathlib import Path

from scale_api import (
    auth,
    db,
    keys,
)
from scale_api.db.models import (
    AuthJsonWeKey,
    AuthUser,
    Platform,
)


def init_platforms(data):
    platforms = db.store.platforms()
    if platforms:
        print('Platforms exist, skipping')
        return
    with db.SessionLocal.begin() as session:
        for platform in data['platforms']:
            new_plat = Platform(**platform)
            session.add(new_plat)


def init_auth_users(data):
    try:
        with db.SessionLocal.begin() as session:
            for user in data['auth_users']:
                secret = user.pop('client_secret')
                user['client_secret_hash'] = auth.hash_password(secret)
                new_user = AuthUser(**user)
                session.add(new_user)
    except Exception as exc:
        print('AuthUsers update failed', repr(exc))


def init_auth_json_web_keys(data):  # noqa data unused
    web_keys = db.store.json_web_keys()
    if web_keys:
        print('AuthJsonWebKeys exist, skipping')
        return
    with db.SessionLocal.begin() as session:
        web_key = keys.generate_private_key()
        jwk = AuthJsonWeKey(
            kid=web_key.kid,
            data=web_key.data.get_secret_value(),
        )
        session.add(jwk)


def init_db(data) -> None:
    db.Base.metadata.create_all(bind=db.engine)
    init_platforms(data)
    init_auth_users(data)
    init_auth_json_web_keys(data)


def run(seed_file: Path) -> None:
    print('Using DB Engine', db.engine)
    print('Using seed file', seed_file)
    with seed_file.open(mode='r', encoding='utf-8') as f:
        data = json.load(f)
    init_db(data)


def main() -> None:
    seed_file = sys.argv[1] if len(sys.argv) > 1 else 'scale_initdb.json'
    run(Path(seed_file))


if __name__ == '__main__':
    main()

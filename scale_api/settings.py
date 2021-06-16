import secrets
from pathlib import Path
from typing import List, Union

from pydantic import AnyHttpUrl, BaseSettings, validator

BASE_PATH = Path(__file__).parent.parent

VALID_ENVIRONMENTS = ('local', 'sandbox', 'dev', 'prod')

NO_CACHE_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
}


class ScaleSettings(BaseSettings):
    ENV: str = 'local'

    DB_URL: str = f'sqlite:///{BASE_PATH}/scale_db.sqlite?check_same_thread=False'
    DEBUG_DB: bool = False

    DEBUG_APP: bool = False

    PATH_PREFIX: str = '/api'

    SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = 'HS256'
    JWT_ISSUER: str = 'https://scale.fresnostate.edu'
    OAUTH_ACCESS_TOKEN_EXPIRY: int = 3600
    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = [
        'http://localhost',
        'http://localhost:8080'
    ]
    SESSION_MAX_AGE: int = 60 * 60 * 12  # 12 hours
    THREAD_POOL_WORKERS: int = 10

    USE_SSL_FOR_APP_RUN_LOCAL: bool = True

    @validator('ENV')
    def verify_environment(cls, v: str) -> str:
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(
                f'Invalid environment [{v}], must be one of: '
                f'{" ".join(VALID_ENVIRONMENTS)}'
            )
        return v

    @validator('DB_URL')
    def verify_sqlite_only_local(cls, v: str, values: dict) -> str:
        if v.startswith('sqlite') and values['ENV'] != 'local':
            raise ValueError(
                'Sqlite DB_URL should only be used in local environments'
            )
        return v

    @validator('BACKEND_CORS_ORIGINS', pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    @property
    def is_production(self) -> bool:
        return self.ENV == 'prod'

    class Config:
        env_file = BASE_PATH / '.env'
        env_prefix = 'SCALE_'

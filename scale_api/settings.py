"""
Application Settings and Configuration

Application-wide configuration settings that are read in from the Environment.
"""
import functools
import logging.config
import secrets
from pathlib import Path
from typing import Any

from pydantic import BaseSettings, validator

BASE_PATH = Path(__file__).parent.parent

VALID_ENVIRONMENTS = ("local", "sandbox", "dev", "prod")


class SharedSettings(BaseSettings):
    class Config:
        env_file = BASE_PATH / ".env"


class LogSettings(SharedSettings, env_prefix="LOG_"):
    level_root: str = "WARNING"
    level_app: str = "INFO"


class DatabaseSettings(SharedSettings, env_prefix="SCALE_DB_"):
    url: str = f"sqlite:///{BASE_PATH}/scale_db.sqlite?check_same_thread=False"
    debug: bool = False
    seed_file: Path | None = None


class APISettings(SharedSettings, env_prefix="SCALE_"):
    """Main app settings.

    The attributes are populated from OS environment variables that are
    prefixed by ``SCALE_``.
    """

    env: str = "local"
    debug_app: bool = False
    path_prefix: str = "/api"
    secret_key: str = secrets.token_urlsafe(32)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "https://scale.fresnostate.edu"
    oauth_access_token_expiry: int = 3600
    thread_pool_workers: int = 10
    use_ssl_for_app_run_local: bool = True
    frontend_launch_path: str = "/dyna/payload.php"

    @validator("env")
    def verify_environment(cls, v: str) -> str:  # noqa: N805
        """Raises a ``ValueError`` if the provided environment is not valid."""
        if v not in VALID_ENVIRONMENTS:
            msg = f"Invalid env [{v}], must be one of: {' '.join(VALID_ENVIRONMENTS)}"
            raise ValueError(msg)

        db_url = DatabaseSettings().url
        if db_url.startswith("sqlite") and v != "local":
            msg = "Sqlite DB_URL should only be used in local environments"
            raise ValueError(msg)

        return v

    @property
    def is_production(self) -> bool:
        """Returns True if the environment is set to Production mode."""
        return self.env == "prod"

    @property
    def is_local(self) -> bool:
        """Returns True if the environment is set to Local model."""
        return self.env == "local"


class AppConfig:
    """Application configuration.

    Provides cached access to all application configuration classes.
    """

    def __init__(self) -> None:
        logging.config.dictConfig(self.log_config)

    @property
    def base_path(self) -> Path:
        return BASE_PATH

    @functools.cached_property
    def api(self) -> APISettings:
        return APISettings()

    @functools.cached_property
    def db(self) -> DatabaseSettings:
        return DatabaseSettings()

    @functools.cached_property
    def log(self) -> LogSettings:
        return LogSettings()

    @functools.cached_property
    def log_config(self) -> dict[str, Any]:
        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "basic": {
                    "format": "%(asctime)s[%(levelname)s]%(name)s: %(message)s",
                    "datefmt": "%Y-%m-%dT%H:%M:%S",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "basic",
                    "stream": "ext://sys.stdout",
                },
            },
            "loggers": {
                "": {
                    "handlers": ["console"],
                    "level": self.log.level_root,
                },
                "scale_api": {
                    "level": self.log.level_app,
                },
            },
        }


app_config = AppConfig()

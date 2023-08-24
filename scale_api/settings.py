"""
Application Settings and Configuration

Application-wide configuration settings that are read in from the Environment.
"""
import contextvars
import logging.config
import secrets
from pathlib import Path
from typing import Any

import pydantic_settings
from pydantic import field_validator

BASE_PATH = Path(__file__).parent.parent

VALID_ENVIRONMENTS = ("local", "sandbox", "dev", "prod")

ctx_request_id = contextvars.ContextVar("ctx_request_id", default="-")


class SharedSettings(pydantic_settings.BaseSettings):
    model_config = {"env_file": BASE_PATH / ".env", "frozen": True}


class LogSettings(SharedSettings, env_prefix="LOG_"):
    level_root: str = "WARNING"
    level_app: str = "INFO"
    level_uvicorn: str = "INFO"


class DatabaseSettings(SharedSettings, env_prefix="SCALE_DB_"):
    url: str = (
        f"sqlite+aiosqlite:///{BASE_PATH}/scale_db.sqlite?check_same_thread=False"
    )
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
    port: int = 8000
    secret_key: str = secrets.token_urlsafe(32)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "https://scale.fresnostate.edu"
    oauth_access_token_expiry: int = 3600
    use_ssl_for_app_run_local: bool = True
    frontend_launch_path: str = "/dyna/payload.php"

    @field_validator("env")
    def _verify_environment(cls, v: str) -> str:
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


api = APISettings()
db = DatabaseSettings()
log = LogSettings()

old_factory = logging.getLogRecordFactory()


def log_record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = old_factory(*args, **kwargs)
    record.request_id = ctx_request_id.get()
    return record


logging.setLogRecordFactory(log_record_factory)
logging.basicConfig(
    format="%(asctime)s[%(levelname)s][%(request_id)s]%(name)s: %(message)s"
)
logging.getLogger("").setLevel(log.level_root)
logging.getLogger("uvicorn").setLevel(log.level_uvicorn)
logging.getLogger("scale_api").setLevel(log.level_app)

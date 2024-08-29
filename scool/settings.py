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
Application Settings and Configuration

Application-wide configuration settings that are read in from the Environment.
"""

import contextvars
import dataclasses
import logging
import secrets
from pathlib import Path
from typing import Any

import dotenv
import pydantic_settings
import shortuuid
from pydantic import field_validator

BASE_PATH = Path(__file__).parent.parent

VALID_ENVIRONMENTS = ("local", "sandbox", "dev", "prod")

dotenv.load_dotenv()


@dataclasses.dataclass(frozen=True)
class RequestContext:
    """Context information to pass from routes to other services."""

    request_id: str
    client_ip: str


ctx_request: contextvars.ContextVar[RequestContext] = contextvars.ContextVar(
    "RequestContext",
    default=RequestContext(
        request_id=shortuuid.uuid(),
        client_ip="0.0.0.0",  # noqa:S104
    ),
)


class SharedSettings(pydantic_settings.BaseSettings):
    model_config = {"frozen": True}


class LogSettings(SharedSettings, env_prefix="LOG_"):
    level_root: str = "WARNING"
    level_app: str = "INFO"
    level_uvicorn: str = "INFO"


class DatabaseSettings(SharedSettings, env_prefix="SCOOL_DB_"):
    url: str = (
        f"sqlite+aiosqlite:///{BASE_PATH}/scool_db.sqlite?check_same_thread=False"
    )
    debug: bool = False


class FeatureSettings(SharedSettings, env_prefix="SCOOL_FEATURE_"):
    # legacy claim used by dotnet
    legacy_unique_name_claim: bool = True


class APISettings(SharedSettings, env_prefix="SCOOL_"):
    """Main app settings.

    The attributes are populated from OS environment variables that are
    prefixed by ``SCOOL_``.
    """

    env: str = "local"
    debug_app: bool = False
    path_prefix: str = "/api"
    port: int = 8000
    secret_key: str = secrets.token_urlsafe(32)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "https://scool.fresnostate.edu"
    oauth_access_token_expiry: int = 3600
    use_ssl_for_app_run_local: bool = True
    frontend_launch_path: str = "/dyna/payload.php"
    frontend_api_key: str = f"TEST-{secrets.token_urlsafe(16)}"

    @field_validator("env")
    def _verify_environment(cls, v: str) -> str:
        """Raises a ``ValueError`` if the provided environment is not valid."""
        if v not in VALID_ENVIRONMENTS:
            msg = f"Invalid env [{v}], must be one of: {" ".join(VALID_ENVIRONMENTS)}"
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
features = FeatureSettings()

_old_log_factory = logging.getLogRecordFactory()


def _new_log_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _old_log_factory(*args, **kwargs)
    record.request_id = ctx_request.get().request_id
    return record


logging.setLogRecordFactory(_new_log_factory)
logging.basicConfig(
    format="%(asctime)s[%(levelname)s][%(request_id)s]%(name)s: %(message)s",
    level=log.level_root,
)
logging.getLogger(__package__).setLevel(log.level_app)
logging.getLogger("uvicorn").setLevel(log.level_uvicorn)
# avoid logging a Traceback from passlib failing to read the bcrypt version
logging.getLogger("passlib.handlers.bcrypt").setLevel(logging.ERROR)

if api.is_local:
    logging.error("Frontend API Key: %s", api.frontend_api_key)
elif api.frontend_api_key.startswith("TEST-"):
    raise RuntimeError("SCOOL_FRONTEND_API_KEY must be set")  # noqa: TRY003

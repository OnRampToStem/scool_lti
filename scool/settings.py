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

import shortuuid
from starlette.config import Config

BASE_PATH = Path(__file__).parent.parent

VALID_ENVIRONMENTS = ("local", "sandbox", "dev", "prod")

_cfg = Config(env_file=BASE_PATH / ".env")


@dataclasses.dataclass(frozen=True)
class RequestContext:
    """Context information to pass from routes to other services."""

    request_id: str
    client_ip: str | None


CTX_REQUEST: contextvars.ContextVar[RequestContext] = contextvars.ContextVar(
    "RequestContext",
    default=RequestContext(  # noqa: B039
        request_id=shortuuid.uuid(),
        client_ip=None,
    ),
)

DEBUG = _cfg("SCOOL_DEBUG", cast=bool, default=False)
DEVMODE = _cfg("API_DEVMODE", cast=bool, default=False)
ENV = _cfg("SCOOL_ENV", default="local")
SECRET_KEY = _cfg("SCOOL_SECRET_KEY", default=secrets.token_urlsafe(32))
PORT = _cfg("SCOOL_PORT", cast=int, default=8443)
PATH_PREFIX = _cfg("SCOOL_PATH_PREFIX", default="/api")
FORWARDED_ALLOW_CIDRS = _cfg(
    "SCOOL_FORWARDED_ALLOW_CIDRS", default="172.16.0.0/12,10.20.80.0/22,10.20.95.0/27"
)

JWT_ALGORITHM = _cfg("SCOOL_JWT_ALGORITHM", default="HS256")
JWT_ISSUER = _cfg("SCOOL_JWT_ISSUER", default="https://scool.fresnostate.edu")

OAUTH_ACCESS_TOKEN_EXPIRY = _cfg(
    "SCOOL_OAUTH_ACCESS_TOKEN_EXPIRY", cast=int, default=3600
)

FRONTEND_LAUNCH_PATH = _cfg("SCOOL_FRONTEND_LAUNCH_PATH", default="/dyna/payload.php")
FRONTEND_API_KEY = _cfg(
    "SCOOL_FRONTEND_API_KEY", default=f"TEST-{secrets.token_urlsafe(16)}"
)

DB_URL = _cfg(
    "SCOOL_DB_URL",
    default=f"sqlite+aiosqlite:///{BASE_PATH}/scool_db.sqlite?check_same_thread=False",
)

LOG_LEVEL_ROOT = _cfg("LOG_LEVEL_ROOT", default="INFO" if DEBUG else "WARNING")
LOG_LEVEL_UVICORN = _cfg("LOG_LEVEL_UVICORN", default="DEBUG" if DEBUG else "INFO")
LOG_LEVEL_APP = _cfg("LOG_LEVEL_APP", default="DEBUG" if DEBUG else "INFO")

_old_log_factory = logging.getLogRecordFactory()


def _new_log_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _old_log_factory(*args, **kwargs)
    record.request_id = CTX_REQUEST.get().request_id
    return record


logging.setLogRecordFactory(_new_log_factory)
logging.basicConfig(
    format="%(asctime)s[%(levelname)s][%(request_id)s]%(name)s: %(message)s",
    level=LOG_LEVEL_ROOT,
)
logging.getLogger("uvicorn").setLevel(LOG_LEVEL_UVICORN)
logging.getLogger(__package__).setLevel(LOG_LEVEL_APP)
# avoid logging a Traceback from passlib failing to read the bcrypt version
logging.getLogger("passlib.handlers.bcrypt").setLevel(logging.ERROR)


def verify_environment(value: str) -> None:
    """Raises a ``ValueError`` if the provided environment is not valid."""
    if value not in VALID_ENVIRONMENTS:
        msg = f"Invalid env [{value}], must be one of: {' '.join(VALID_ENVIRONMENTS)}"
        raise ValueError(msg)

    if DB_URL.startswith("sqlite") and value != "local":
        msg = "Sqlite DB_URL should only be used in local environments"
        raise ValueError(msg)


def is_production() -> bool:
    """Returns True if the environment is set to Production mode."""
    return ENV == "prod"


def is_local() -> bool:
    """Returns True if the environment is set to Local model."""
    return ENV == "local"


verify_environment(ENV)

if is_local():
    logging.error("Frontend API Key: %s", FRONTEND_API_KEY)
elif FRONTEND_API_KEY.startswith("TEST-"):
    raise RuntimeError("SCOOL_FRONTEND_API_KEY must be set")  # noqa: TRY003

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

import uuid

import sqlalchemy.exc
import sqlalchemy.orm
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from .. import settings

IntegrityError = sqlalchemy.exc.IntegrityError
Session = sqlalchemy.orm.Session

engine = create_async_engine(
    settings.db.url,
    echo=settings.db.debug,
    pool_recycle=3600,
)

async_session = async_sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def new_uuid() -> str:
    """Return a UUID as a 32-character hex string."""
    return uuid.uuid4().hex

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

import uuid

import sqlalchemy as sa
import sqlalchemy.exc
import sqlalchemy.orm

from ..settings import app_config

IntegrityError = sqlalchemy.exc.IntegrityError
Session = sqlalchemy.orm.Session

engine = sa.create_engine(
    app_config.db.url,
    echo=app_config.db.debug,
    pool_recycle=3600,
)

SessionLocal = sqlalchemy.orm.sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def new_uuid() -> str:
    """Return a UUID as a 32-character hex string."""
    return uuid.uuid4().hex

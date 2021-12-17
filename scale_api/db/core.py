import uuid

import sqlalchemy as sa
import sqlalchemy.ext.declarative
import sqlalchemy.orm

from scale_api import app_config

Session = sqlalchemy.orm.Session

engine = sa.create_engine(
    app_config.DB_URL,
    future=True,
    echo=app_config.DEBUG_DB,
)

SessionLocal = sqlalchemy.orm.sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True
)

Base = sqlalchemy.ext.declarative.declarative_base()


def new_uuid() -> str:
    """Return a UUID as a 32-character hex string."""
    return uuid.uuid4().hex
import json
import logging
import uuid
from typing import List

import sqlalchemy as sa
import sqlalchemy.ext.declarative
import sqlalchemy.orm

from scale_api import (
    aio,
    app_config,
    schemas,
)

logger = logging.getLogger(__name__)

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
    return uuid.uuid4().hex


class Platform(Base):
    __tablename__ = 'platforms'

    id = sa.Column(sa.String(32), primary_key=True, default=new_uuid)
    name = sa.Column(sa.String(100), nullable=False)
    issuer = sa.Column(sa.Text())
    oidc_auth_url = sa.Column(sa.Text())
    auth_token_url = sa.Column(sa.Text(), nullable=True)
    jwks_url = sa.Column(sa.Text())
    client_id = sa.Column(sa.String(128), nullable=True)
    client_secret = sa.Column(sa.String(128), nullable=True)

    # TODO: should there be a `PlatformDeployment` model in case the tool is deployed multiple times??

    def __repr__(self) -> str:
        return f'Platform(id={self.id!r}, name={self.name!r})'


class AuthUser(Base):
    __tablename__ = 'auth_users'

    id = sa.Column(sa.String(32), primary_key=True, default=new_uuid)
    client_id = sa.Column(sa.String(128), nullable=False)
    client_secret_hash = sa.Column(sa.String(128), nullable=True)
    scopes = sa.Column(sa.Text, nullable=True)
    is_active = sa.Column(sa.Boolean(), default=True)
    is_superuser = sa.Column(sa.Boolean, default=False)
    is_verified = sa.Column(sa.Boolean, default=False)

    def __repr__(self) -> str:
        return (
            'AuthUser('
            f'client_id={self.client_id!r}'
            f', is_active={self.is_active}'
            f', is_superuser={self.is_superuser}'
            f', is_verified={self.is_verified}'
            ')'
        )


# Ensure `AuthUser.client_id` is unique case-insensitively
sa.Index('ix_auth_user_client_id_ci', sa.func.lower(AuthUser.client_id), unique=True)


class AuthJsonWeKey(Base):
    __tablename__ = 'auth_jwks'

    kid = sa.Column(sa.String(64), primary_key=True)
    data = sa.Column(sa.Text, nullable=False)
    valid_from = sa.Column(sa.DateTime, server_default=sa.func.now())
    valid_to = sa.Column(sa.DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            'AuthJsonWeKey('
            f'kid={self.kid!r}'
            f', valid_from={self.valid_from}'
            f', valid_to={self.valid_to}'
            ')'
        )


class Message(Base):
    __tablename__ = 'messages'

    id = sa.Column(sa.String(36), primary_key=True, default=new_uuid)
    subject = sa.Column(sa.String(255), index=True)
    header = sa.Column(sa.Text, nullable=True)
    body = sa.Column(sa.Text)
    status = sa.Column(sa.String(10), default='active')
    created_at = sa.Column(sa.DateTime, default=sa.func.now())
    updated_at = sa.Column(sa.DateTime, default=sa.func.now(), onupdate=sa.func.now())

    def __repr__(self) -> str:
        return (
            'Message('
            f'id={self.id!r}'
            f', subject={self.subject!r}'
            f', status={self.status!r}'
            f', created_at={self.created_at}'
            f', updated_at={self.updated_at}'
            ')'
        )


class ScaleStore:

    def platforms(self) -> List[schemas.Platform]:
        with SessionLocal.begin() as session:
            stmt = sa.select(Platform)
            result = session.execute(stmt)
            platforms = [
                schemas.Platform.from_orm(row)
                for row in result.scalars()
            ]

        return platforms

    def platform(self, platform_id) -> schemas.Platform:
        with SessionLocal.begin() as session:
            stmt = sa.select(Platform).where(Platform.id == platform_id)
            result = session.execute(stmt).scalar()
            if not result:
                raise LookupError(platform_id)
            platform = schemas.Platform.from_orm(result)
        return platform

    def user(self, user_id: str) -> schemas.AuthUser:
        with SessionLocal.begin() as session:
            result = session.get(AuthUser, user_id)
            logger.info('user(%s)==%s', user_id, result)
            if not result:
                raise LookupError(user_id)
            user = schemas.AuthUser.from_orm(result)
        return user

    def user_by_client_id(self, client_id: str) -> schemas.AuthUser:
        with SessionLocal.begin() as session:
            stmt = sa.select(AuthUser).where(
                sa.func.lower(AuthUser.client_id) == client_id.lower()
                and not AuthUser.disabled
            )
            result = session.execute(stmt).scalar()
            logger.info('user_by_client_id(%s)==%s', client_id, result)
            if not result:
                raise LookupError(client_id)
            user = schemas.AuthUser.from_orm(result)
        return user

    def firebase_entries(self, object_name: str) -> dict:
        # TODO: handle pagination
        stmt = sa.text("""
            select "Id", "Data"
            from "FirebaseCompatEntries"
            where "ObjectName" = :object_name        
        """)
        # TODO: should we validate object_name matches something expected?
        bind_params = {'object_name': object_name}
        with SessionLocal.begin() as session:
            result = session.execute(stmt, bind_params)
            return {guid: json.loads(data) for guid, data in result}

    def firebase_entry(self, object_name: str, object_guid: str) -> dict:
        stmt = sa.text("""
            select "Data"
            from "FirebaseCompatEntries"
            where "Id" = :object_guid
              and "ObjectName" = :object_name
        """)
        bind_params = {'object_guid': object_guid, 'object_name': object_name}
        with SessionLocal.begin() as session:
            result = session.execute(stmt, bind_params)
            # TODO: what if not found? 404 or other error, has does dotnet handle it?
            return json.loads(result.scalar())

    def json_web_keys(self) -> List[schemas.AuthJsonWebKey]:
        with SessionLocal.begin() as session:
            stmt = sa.select(AuthJsonWeKey).where(
                AuthJsonWeKey.valid_from <= sa.func.now(),
                sa.or_(
                    AuthJsonWeKey.valid_to == None,
                    AuthJsonWeKey.valid_to > sa.func.now(),
                )
            )
            result = session.execute(stmt).scalars()
            keys = [
                schemas.AuthJsonWebKey.from_orm(row)
                for row in result
            ]
        return keys

    platforms_async = aio.wrap(platforms)
    platform_async = aio.wrap(platform)
    user_async = aio.wrap(user)
    user_by_client_id_async = aio.wrap(user_by_client_id)
    firebase_entries_async = aio.wrap(firebase_entries)
    firebase_entry_async = aio.wrap(firebase_entry)
    json_web_keys_async = aio.wrap(json_web_keys)


class MessageStore:

    def messages(self, subject: str) -> List[schemas.Message]:
        stmt = sa.select(Message).where(
            Message.subject == subject,
            Message.status == 'active',
        )
        with SessionLocal.begin() as session:
            result = session.execute(stmt)
            entry_list = [
                schemas.Message.from_orm(row)
                for row in result.scalars()
            ]

        return entry_list

    def message(self, msg_id: str, subject: str) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            assert msg.subject == subject, f'{msg.subject} != {subject}'
            return schemas.Message.from_orm(msg)

    def create(self, subject: str, body: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = Message(subject=subject, header=header, body=body)
            session.add(msg)
            session.flush()
            return schemas.Message.from_orm(msg)

    def update(self, msg_id: str, subject: str, body: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if not (msg.subject == subject and msg.body == body and msg.header == header):
                msg.subject = subject
                msg.body = body
                msg.header = header
            session.flush()
            return schemas.Message.from_orm(msg)

    def delete(self, msg_id: str, subject: str) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            assert msg.subject == subject, f'{msg.subject} != {subject}'
            msg.status = 'deleted'
            session.flush()
            return schemas.Message.from_orm(msg)

    messages_async = aio.wrap(messages)
    message_async = aio.wrap(message)
    create_async = aio.wrap(create)
    update_async = aio.wrap(update)
    delete_async = aio.wrap(delete)


store = ScaleStore()
message_store = MessageStore()

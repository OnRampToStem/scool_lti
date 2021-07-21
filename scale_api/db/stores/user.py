import logging
from typing import List

from scale_api import aio, schemas
from ..core import SessionLocal, sa
from ..models import Message

logger = logging.getLogger(__name__)


class UserStore:
    """Users Repository."""

    def users(self, subject: str) -> List[schemas.Message]:
        if subject.endswith('%'):
            stmt = sa.select(Message).where(
                Message.subject.like(subject),
                Message.status == 'active',
            )
        else:
            stmt = sa.select(Message).where(
                Message.subject == subject,
                Message.status == 'active',
            )
        with SessionLocal() as session:
            result = session.execute(stmt)
            entry_list = [
                schemas.Message.from_orm(row)
                for row in result.scalars()
            ]

        return entry_list

    def user(self, user_key: str) -> schemas.Message:
        with SessionLocal() as session:
            msg = session.get(Message, user_key)
            if not msg:
                raise LookupError(user_key)
            if not msg.subject.startswith('users.'):
                raise ValueError(f'Not a user entry: %s', msg.subject)
            return schemas.Message.from_orm(msg)

    def create(self, user_key: str, subject: str, body: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = Message(id=user_key, subject=subject, header=header, body=body)
            session.add(msg)
            session.flush()
            return schemas.Message.from_orm(msg)

    def update(self, user_key: str, subject: str, body: str) -> schemas.Message:
        with SessionLocal.begin() as session:
            user = session.get(Message, user_key)
            if not user:
                raise LookupError(user_key)
            if not user.subject.startswith(subject):
                raise ValueError(f'Update subject mismatch: actual %s, expected: %s',
                                 user.subject, subject)
            if user.body != body:
                user.body = body
            session.flush()
            return schemas.Message.from_orm(user)

    def delete(self, user_key: str, subject: str, header: str = None) -> schemas.Message:
        with SessionLocal.begin() as session:
            user = session.get(Message, user_key)
            if not user:
                raise LookupError(user_key)
            if not user.subject.startswith(subject):
                raise ValueError(f'Delete aborted, mismatched subject: '
                                 'actual: [%s], expected: [%s]',
                                 user.subject, subject)
            if header and user.header != header:
                raise ValueError(f'Delete aborted, mismatched header: '
                                 'actual: [%s], expected: [%s]',
                                 user.header, header)
            user.status = 'deleted'
            session.flush()
            return schemas.Message.from_orm(user)

    users_async = aio.wrap(users)
    user_async = aio.wrap(user)
    create_async = aio.wrap(create)
    update_async = aio.wrap(update)
    delete_async = aio.wrap(delete)

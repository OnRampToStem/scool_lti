import logging
from typing import Iterable

from scale_api import aio, schemas
from ..core import SessionLocal, sa
from ..models import Message

logger = logging.getLogger(__name__)


class UserStore:
    """Users Repository."""

    # noinspection PyMethodMayBeStatic
    def users(self, subject: str) -> Iterable[schemas.Message]:
        if subject.endswith('%'):
            stmt = sa.select(Message).where(
                Message.subject.like(subject),  # noqa ilike
                Message.status == 'active',
            )
        else:
            stmt = sa.select(Message).where(
                Message.subject == subject,
                Message.status == 'active',
            )
        with SessionLocal() as session:
            result = session.execute(stmt)
            for row in result.scalars():
                yield schemas.Message.from_orm(row)

    # noinspection PyMethodMayBeStatic
    def user(self, user_key: str) -> schemas.Message:
        with SessionLocal() as session:
            msg = session.get(Message, user_key)
            if not msg:
                raise LookupError(f'{user_key} not found')
            if msg.status != 'active':
                raise LookupError(f'{user_key} not active')
            if not msg.subject.startswith('users.'):
                raise ValueError(f'Not a user entry: %s', msg.subject)
            return schemas.Message.from_orm(msg)

    # noinspection PyMethodMayBeStatic
    def create(
            self,
            user_key: str,
            subject: str,
            body: str,
            header: str | None = None
    ) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = Message(
                id=user_key,
                subject=subject,
                header=header,
                body=body,
            )
            session.add(msg)
            session.flush()
            return schemas.Message.from_orm(msg)

    # noinspection PyMethodMayBeStatic
    def update(self, user_key: str, subject: str, body: str) -> schemas.Message:
        with SessionLocal.begin() as session:
            user = session.get(Message, user_key)
            if not user:
                raise LookupError(user_key)
            if not user.subject.startswith(subject):
                raise ValueError(f'Update subject mismatch: %s, expected: %s',
                                 user.subject, subject)
            if user.status != 'active':
                user.status = 'active'
            if user.body != body:
                user.body = body
            session.flush()
            return schemas.Message.from_orm(user)

    # noinspection PyMethodMayBeStatic
    def delete(
            self,
            user_key: str,
            subject: str,
            header: str | None = None,
    ) -> schemas.Message:
        with SessionLocal.begin() as session:
            user = session.get(Message, user_key)  # noqa duplicate code
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
            if user.status != 'deleted':
                user.status = 'deleted'
                session.flush()
            return schemas.Message.from_orm(user)

    users_async = aio.wrap(users)
    user_async = aio.wrap(user)
    create_async = aio.wrap(create)
    update_async = aio.wrap(update)
    delete_async = aio.wrap(delete)

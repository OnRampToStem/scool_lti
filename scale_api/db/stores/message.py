import logging

import sqlalchemy as sa

from scale_api import aio, schemas

from ..core import SessionLocal
from ..models import Message

logger = logging.getLogger(__name__)


class MessageStore:
    """Messages Repository."""

    # noinspection PyMethodMayBeStatic
    def messages(self, subject: str) -> list[schemas.Message]:
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

    # noinspection PyMethodMayBeStatic
    def message(self, msg_id: str, subject: str) -> schemas.Message:
        with SessionLocal() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if msg.subject != subject:
                raise ValueError('Update subject mismatch: actual != expected',
                                 msg.subject, subject)
            return schemas.Message.from_orm(msg)

    # noinspection PyMethodMayBeStatic
    def create(
            self,
            subject: str,
            body: str,
            header: str | None = None,
    ) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = Message(subject=subject, header=header, body=body)
            session.add(msg)
            session.flush()
            return schemas.Message.from_orm(msg)

    # noinspection PyMethodMayBeStatic
    def update(
            self,
            msg_id: str,
            subject: str,
            body: str,
            header: str | None = None,
    ) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if msg.subject != subject:
                raise ValueError('Update subject mismatch: actual!= expected',
                                 msg.subject, subject)
            if msg.header != header:
                raise ValueError('Update header mismatch: actual != expected',
                                 msg.header, header)
            if msg.body != body:
                msg.body = body
            session.flush()
            return schemas.Message.from_orm(msg)

    # noinspection PyMethodMayBeStatic,DuplicatedCode
    def delete(
            self,
            msg_id: str,
            subject: str,
            header: str | None = None,
    ) -> schemas.Message:
        with SessionLocal.begin() as session:
            msg = session.get(Message, msg_id)
            if not msg:
                raise LookupError(msg_id)
            if not (msg.subject and msg.subject.startswith(subject)):
                raise ValueError('Delete aborted, mismatched subject: '
                                 'actual != expected',
                                 msg.subject, subject)
            if header and msg.header != header:
                raise ValueError('Delete aborted, mismatched header: '
                                 'actual != expected',
                                 msg.header, header)
            msg.status = 'deleted'
            session.flush()
            return schemas.Message.from_orm(msg)

    messages_async = aio.wrap(messages)
    message_async = aio.wrap(message)
    create_async = aio.wrap(create)
    update_async = aio.wrap(update)
    delete_async = aio.wrap(delete)

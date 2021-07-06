"""
Messages routes

Provides a CRUD interface to the Messages table. Allows for storing
text blobs, mostly in JSON format, for the front-end webapp.
"""
import json
import logging
from typing import List

from fastapi import (
    APIRouter,
    Body,
    HTTPException,
    Request,
    status
)

from scale_api import (
    db,
    schemas,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get('/{subject}.json', response_model=List[schemas.Message])
async def get_messages(subject: str):
    entries = await db.message_store.messages_async(subject)
    return entries


@router.get('/{subject}/{msg_id}.json', response_model=schemas.Message)
async def get_message(subject: str, msg_id: str):
    try:
        msg = await db.message_store.message_async(msg_id, subject)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    else:
        assert msg.subject == subject, f'{msg.subject} != {subject}'
        return msg


@router.post('/{subject}.json', response_model=schemas.Message)
async def create_message(request: Request, subject: str, body: dict = Body(...)):
    check_access(request, subject, 'post', body)
    # TODO: extract header from body?
    body = json.dumps(body)
    msg = await db.message_store.create_async(subject, body)
    return msg


@router.put('/{subject}/{msg_id}.json', response_model=schemas.Message)
async def update_message(request: Request, subject: str, msg_id: str, body: dict = Body(...)):
    check_access(request, subject, 'put', body)
    try:
        body = json.dumps(body)
        msg = await db.message_store.update_async(msg_id, subject, body)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    else:
        return msg


@router.delete('/{subject}/{msg_id}.json', status_code=status.HTTP_202_ACCEPTED)
async def delete_message(request: Request, subject: str, msg_id: str):
    check_access(request, subject, 'delete')
    try:
        msg = await db.message_store.delete_async(msg_id, subject)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    logger.warning('Deleted message: %s', msg)


def check_access(request: Request, subject: str, action: str, body: dict = None) -> None:
    auth_user: schemas.AuthUser = request.state.auth_user
    logger.info('Checking Message %s/%s access for user %s',
                subject, action, auth_user)

    if auth_user.is_superuser:
        return

    for scope in auth_user.scopes:
        if scope.lower() in ('role:dev', 'role:admin', 'role:instructor'):
            return

    # Allow user to update their own users message
    if subject == 'users':
        if body and auth_user.client_id == body.get('username'):
            return
        else:
            if not body:
                logger.error('Messages.users body is blank')
            else:
                logger.error('Messages.users username does not match: %s, %s',
                             auth_user.client_id, body.get('username'))

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

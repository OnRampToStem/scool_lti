"""
Messages routes

Provides a CRUD interface to the Messages table. Allows for storing
text blobs, mostly in JSON format, for the front-end webapp.
"""
import json
import logging
from typing import List, Mapping, Union

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
async def get_messages(request: Request, subject: str):
    entries = await db.message_store.messages_async(subject)
    return [e for e in entries if can_access(request, subject, 'get', e.body)]


@router.get('/{subject}/{msg_id}.json', response_model=schemas.Message)
async def get_message(request: Request, subject: str, msg_id: str):
    try:
        msg = await db.message_store.message_async(msg_id, subject)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    else:
        assert msg.subject == subject, f'{msg.subject} != {subject}'
        check_access(request, subject, 'get', msg.body)
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
    # Verify the new message is authorized
    check_access(request, subject, 'put', body)
    try:
        old_msg = await db.message_store.message_async(msg_id, subject)
        # Verify request is authorized to replace this specific message
        check_access(request, subject, 'put', old_msg.body)
        body = json.dumps(body)
        msg = await db.message_store.update_async(msg_id, subject, body)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    else:
        return msg


@router.delete('/{subject}/{msg_id}.json', status_code=status.HTTP_202_ACCEPTED)
async def delete_message(request: Request, subject: str, msg_id: str):
    # Verify request is authorized for this action
    check_access(request, subject, 'delete')
    try:
        old_msg = await db.message_store.message_async(msg_id, subject)
        # Verify request is authorized to delete this specific message
        check_access(request, subject, 'delete', old_msg.body)
        msg = await db.message_store.delete_async(msg_id, subject)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    logger.warning('Deleted message: %s', msg)


def check_access(
        request: Request,
        subject: str,
        action: str,
        body: Union[str, dict] = None
) -> None:
    """Checks that the requested access is allowed, else raises an HTTP 403."""
    if not can_access(request, subject, action, body):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def can_access(
        request: Request,
        subject: str,
        action: str,
        body: Union[str, dict] = None
) -> bool:
    """Returns True if this request is permitted, else False."""
    auth_user: schemas.AuthUser = request.state.auth_user
    logger.debug('Checking Message %s/%s access for user %s',
                 subject, action, auth_user)

    if auth_user.is_superuser:
        return True

    for scope in auth_user.scopes:
        if scope.lower() in ('role:admin', 'role:developer', 'role:editor'):
            return True

    if action == 'delete':
        logger.error('Messages.%s delete action disallowed for AuthUser: %s',
                     subject, auth_user)
        return False

    # Allow user to update their own users message
    if subject == 'users':
        auth_username = auth_user.client_id
        if not body:
            logger.error('Messages.users body is blank')
            return False
        elif isinstance(body, str) and auth_username in body:
            return True
        elif isinstance(body, Mapping) and auth_username == body.get('username'):
            return True
        else:
            return False
    else:
        return action == 'get'

"""
Messages routes

Provides a CRUD interface to the Messages table. Allows for storing
text blobs, mostly in JSON format, for the front-end webapp.
"""
import json
import logging
from typing import Any, Union

from fastapi import APIRouter, Body, HTTPException, Request, status

from scale_api import (
    db,
    schemas,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get('/{subject}.json', response_model=list[schemas.Message])
async def get_messages(request: Request, subject: str):
    entries = await db.message_store.messages_async(subject)
    logger.debug('Messages.%s found %s entries in db', subject, len(entries))
    result = [
        e for e in entries
        if can_access(request, subject, 'get', e.body)
    ]
    logger.debug('Messages.%s found %s permitted', subject, len(result))
    return result


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
async def create_message(request: Request, subject: str, body: dict[str, Any] = Body(...)):
    check_access(request, subject, 'post', body)
    # TODO: extract header from body?
    body_text = json.dumps(body)
    msg = await db.message_store.create_async(subject, body_text)
    return msg


@router.put('/{subject}/{msg_id}.json', response_model=schemas.Message)
async def update_message(request: Request, subject: str, msg_id: str, body: dict[str, Any] = Body(...)):
    # Verify the new message is authorized
    check_access(request, subject, 'put', body)
    try:
        old_msg = await db.message_store.message_async(msg_id, subject)
        # Verify request is authorized to replace this specific message
        check_access(request, subject, 'put', old_msg.body)
        raw_body = json.dumps(body)
        msg = await db.message_store.update_async(msg_id, subject, raw_body)
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
        body: str | dict[str, Any] | None = None
) -> None:
    """Checks that the requested access is allowed, else raises an HTTP 403."""
    if not can_access(request, subject, action, body):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


def can_access(
        request: Request,
        subject: str,
        action: str,
        body: Union[str, dict[str, Any]] | None = None,  # noqa unused
) -> bool:
    """Returns True if this request is permitted, else False."""
    auth_user: schemas.AuthUser = request.state.auth_user
    logger.debug('Checking Message %s/%s access for user %s',
                 subject, action, auth_user)

    if auth_user.is_superuser:
        return True

    if auth_user.scopes is None:
        user_scopes = set()
    else:
        user_scopes = {scope.lower() for scope in auth_user.scopes}
    for scope in user_scopes:
        if scope in ('role:admin', 'role:developer', 'role:editor'):
            return True
        if scope == 'role:instructor':
            # TODO: need to add security at some point to they can only see
            #       students in their course
            return True

    if action == 'delete':
        logger.error('Messages.%s delete action disallowed for AuthUser: %s',
                     subject, auth_user)
        return False

    if subject == 'users':
        logger.error('Messages.users called but not expected')
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    else:
        return action == 'get'

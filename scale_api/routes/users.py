"""
Users route

We store users to make them easy to retrieve per platform/course.

subject: users.<platform_id>.<context_id>
header:  scale_user.user_id
"""
import hashlib
import json
import logging
from typing import Iterable

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    status,
)
from fastapi.responses import StreamingResponse

from scale_api import (
    auth,
    db,
    schemas,
)

logger = logging.getLogger(__name__)

router = APIRouter()

ROLES_ALL_USERS = {'superuser', 'admin', 'developer'}


def stream_users(subject: str) -> Iterable[bytes]:
    yield b'{'
    i = 0
    for msg in db.user_store.users(subject):
        if i != 0:
            yield b','
        yield f'"{msg.id}":{msg.body}'.encode('utf-8')
        i += 1
    yield b'}'

    logger.info('Streamed [%s] users for subject: %s', i, subject)


@router.get('/')
async def get_users(
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    logger.debug('Users.get_users::ScaleUser(%s)', scale_user)

    # For students only return their entry
    if scale_user.is_student:
        user_key = users_key(scale_user)
        return await get_user(user_key, scale_user)

    if can_access_all_users(scale_user):
        subject = 'users.%'
        logger.info('Users.get_users::ScaleUser(%s) - admin access',
                    scale_user.email)
    else:
        # Instructors subject will return users for their course (context)
        subject = users_subject(scale_user)
        logger.info('Users.get_users::ScaleUser(%s) - instructor access: %s',
                    scale_user.email, subject)

    # User objects are large (~5MB), so any more than a single user we stream
    # them to conserve memory
    return StreamingResponse(
        stream_users(subject),
        media_type='application/json',
    )


@router.get('/{user_key}')
async def get_user(
        user_key: str,
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    logger.debug('Users.get_user::ScaleUser(%s)', scale_user)

    # Make sure student request is only for their user entry
    if scale_user.is_student and users_key(scale_user) != user_key:
        logger.error('User key mismatch: expected %s, actual %s',
                     user_key, users_key(scale_user))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    try:
        user = await db.user_store.user_async(user_key)
    except (LookupError, ValueError) as exc:
        if scale_user.is_student:
            # Before the student entry is created a get is issued and so
            # this is expected. We already handled the case where the student
            # tried to request a key that is not there key.
            return {}
        logger.error('Users.get_user(%s) failed: %r', user_key, exc)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    else:
        result = {user.id: json.loads(user.body)}
        if can_access_all_users(scale_user):
            return result
        elif scale_user.is_instructor and users_subject(scale_user) == user.subject:
            return result
        elif scale_user.is_student:
            # We already verified the user_key matches this student
            return result
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


@router.post('/')
async def create_user(
        body: dict = Body(...),
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    logger.debug('Users.create_user::ScaleUser(%s)', scale_user)

    # Make sure a student entry matches on email
    if scale_user.is_student:
        if body.get('username') != scale_user.email:
            logger.error('Users.create_user mismatch. ''username=%s, email=%s',
                         body.get('username'), scale_user.email)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    # TODO: creating a user depends on the ``scale_user`` that is authenticated
    #       we should probably provide another way to create users if there's a
    #       need to have admins or instructors create them.
    key = users_key(scale_user)
    subject = users_subject(scale_user)
    header = scale_user.user_id
    body_text = json.dumps(body)

    # If create fails it is most likely because this user entry already exists,
    # so we fall back to an update
    try:
        user = await db.user_store.create_async(key, subject, body_text, header)
    except Exception as exc:
        logger.warning(
            'Users.create_user failed, trying Users.update_user - %r',
            exc,
        )
        return await update_user(key, body, scale_user)
    else:
        return {user.id: json.loads(user.body)}


@router.put('/{user_key}')
async def update_user(
        user_key: str,
        body: dict = Body(...),
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    logger.debug('Users.update_user::ScaleUser(%s)', scale_user)

    # Make sure student request is only for their user entry
    if scale_user.is_student and users_key(scale_user) != user_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if can_access_all_users(scale_user):
        subject = 'users.'
    else:
        # This ensures that an instructor will only be able to update users
        # that are in their course (context)
        subject = users_subject(scale_user)

    body_text = json.dumps(body)
    user = await db.user_store.update_async(user_key, subject, body_text)
    return {user.id: json.loads(user.body)}


@router.delete('/{user_key}', status_code=status.HTTP_202_ACCEPTED)
async def delete_user(
        user_key: str,
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    logger.debug('Users.delete_user ScaleUser(%s)', scale_user)

    # Make sure student request is only for their user entry
    if scale_user.is_student and users_key(scale_user) != user_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if can_access_all_users(scale_user):
        subject = 'users.'
    elif scale_user.is_instructor:
        # Ensure instructor can only delete an entry for a user in their course
        subject = users_subject(scale_user)
    else:
        # We currently don't support students deleting their own entry
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    try:
        await db.message_store.delete_async(user_key, subject)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)


def users_key(scale_user: schemas.ScaleUser) -> str:
    key = f'users.{scale_user.platform_id}.{scale_user.context_id}.{scale_user.user_id}'
    return hashlib.sha1(key.encode('utf-8')).hexdigest()


def users_subject(scale_user: schemas.ScaleUser) -> str:
    return f'users.{scale_user.platform_id}.{scale_user.context_id}'


def can_access_all_users(scale_user: schemas.ScaleUser) -> bool:
    return True if set(scale_user.roles) & ROLES_ALL_USERS else False

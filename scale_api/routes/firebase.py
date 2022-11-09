"""
Firebase entries

This endpoint is provided for compatibility only. It delegates calls to
the ``messages`` and ``users`` routes. Once the front-end webapp is converted
to use those routes directly or a new scheme for storing the data is defined,
then this module can be removed.
"""
# TODO: remove this after front-end is updated
import json
import logging

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Request,
    status,
)

from scale_api import (
    auth,
    schemas,
)
from scale_api.routes import messages, users

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get('/users.json')
async def get_users(
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    return await users.get_users(scale_user=scale_user)


@router.get('/users/{user_key}.json')
async def get_user(
        user_key: str,
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    return await users.get_user(user_key, scale_user)


@router.post('/users.json')
async def create_user(
        data: dict = Body(...),
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    return await users.create_user(data, scale_user)


@router.put('/users/{user_key}.json')
async def update_user_entry(
        user_key: str, data: dict = Body(...),
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    return await users.update_user(user_key, data, scale_user)


@router.delete('/users/{user_key}.json', status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_entry(
        user_key: str,
        scale_user: schemas.ScaleUser = Depends(auth.request_scale_user),
):
    await users.delete_user(user_key, scale_user)


@router.get('/{object_name}.json')
async def get_entries(request: Request, object_name: str):
    entries = await messages.get_messages(request, object_name)
    return {
        e.id: json.loads(e.body)
        for e in entries
    }


@router.get('/{object_name}/{object_guid}.json')
async def get_entry(request: Request, object_name: str, object_guid: str):
    entry = await messages.get_message(request, object_name, object_guid)
    return json.loads(entry.body)


@router.post('/{object_name}.json')
async def create_entry(request: Request, object_name: str, data: dict = Body(...)):
    entry = await messages.create_message(request, object_name, data)
    return {entry.id: entry.body}


@router.put('/{object_name}/{object_guid}.json')
async def update_entry(request: Request, object_name: str, object_guid: str, data: dict = Body(...)):
    entry = await messages.update_message(request, object_name, object_guid, data)
    return {entry.id: entry.body}


@router.delete('/{object_name}/{object_guid}.json', status_code=status.HTTP_204_NO_CONTENT)
async def delete_entry(request: Request, object_name: str, object_guid: str):
    await messages.delete_message(request, object_name, object_guid)

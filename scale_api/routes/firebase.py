"""
Firebase entries

This endpoint is provided for compatibility only. It delegates calls to
the ``messages`` routes. Once the front-end webapp is converted to use
``messages`` directly or a new scheme for storing the data is defined,
then this module can be removed.
"""
# TODO: remove this after front-end is updated
import json
import logging

from fastapi import (
    APIRouter,
    Body,
    Request,
    status
)

from scale_api.routes import messages

logger = logging.getLogger(__name__)

router = APIRouter()


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

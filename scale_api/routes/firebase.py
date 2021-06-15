from fastapi import APIRouter, Response, status

from scale_api import (
    db,
)

router = APIRouter()


@router.get('/{object_name}.json')
async def get_entries(object_name: str):
    entries = await db.store.firebase_entries_async(object_name)
    return entries


@router.get('/{object_name}/{object_guid}.json')
async def get_entry(object_name: str, object_guid: str):
    entry = await db.store.firebase_entry_async(object_name, object_guid)
    return entry


@router.post('/{object_name}.json')
async def create_entry(object_name: str):
    # TODO: check for fb:write
    return {'object_name': object_name}


@router.put('/{object_name}/{object_guid}.json')
async def update_entry(object_name: str, object_guid: str):
    # TODO: check for fb:write
    return {
        'name': object_name,
        'guid': object_guid,
    }


@router.delete('/{object_name}/{object_guid}.json')
async def delete_entry(response: Response, object_name: str, object_guid: str):
    # TODO: check for fb:write or should it be fb:delete?
    response.status_code = status.HTTP_204_NO_CONTENT

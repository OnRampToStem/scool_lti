"""
Platforms routes
"""
from fastapi import APIRouter, HTTPException, status

from scale_api import (
    db,
    schemas,
)

router = APIRouter()


@router.get('/', response_model=list[schemas.Platform])
async def get_platforms():
    return await db.store.platforms_async()


@router.get('/{platform_id}', response_model=schemas.Platform)
async def get_platform(platform_id: str):
    try:
        platform = await db.store.platform_async(platform_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from None
    else:
        return platform

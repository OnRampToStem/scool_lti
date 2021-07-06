"""
Platforms routes
"""
from typing import List

from fastapi import APIRouter, HTTPException, Request, status

from scale_api import (
    db,
    schemas,
)

router = APIRouter()


@router.get('/', response_model=List[schemas.Platform])
async def get_platforms(request: Request):
    return await db.store.platforms_async()


@router.get('/{platform_id}', response_model=schemas.Platform)
async def get_platform(request: Request, platform_id: str):
    try:
        platform = await db.store.platform_async(platform_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    else:
        return platform

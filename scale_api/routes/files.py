"""
Files routes
"""
import logging
import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse

from scale_api import db

router = APIRouter()

logger = logging.getLogger(__name__)

ROLES_ALLOWED = {
    'role:superuser',
    'role:admin',
    'role:developer',
    'role:editor',
    'role:instructor'
}


def access_check(request: Request) -> None:
    auth_user = request.state.auth_user
    auth_roles = {
        scope.lower()
        for scope in auth_user.scopes
        if scope.startswith('role')
    }
    if not auth_roles & ROLES_ALLOWED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


@router.get('/.test', dependencies=[Depends(access_check)])
async def test_upload(request: Request):
    target_url = request.url_for('put_file', file_id='test-single-file')
    content = f"""\
    <html>
    <body>
        <form action="{target_url}" enctype="multipart/form-data" method="post">
            <input name="file" type="file">
            <input type="submit">
        </form>
    </body>
    </html>
    """
    return HTMLResponse(content=content)


@router.get('/{file_id}')
async def get_file(file_id: str):
    logger.debug('files.get_file(%s)', file_id)
    try:
        result = await db.bin_store.get_async(file_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from None
    else:
        headers = {
            'Content-Disposition': f'inline; filename="{result.name}"',
        }
        return Response(
            content=result.data,
            headers=headers,
            media_type=result.content_type
        )


@router.post('/', dependencies=[Depends(access_check)])
async def post_file(file: UploadFile = File(...)):
    return await put_file(uuid.uuid4().hex, file)


@router.put('/{file_id}', dependencies=[Depends(access_check)])
@router.post('/{file_id}', dependencies=[Depends(access_check)])
async def put_file(file_id: str, file: UploadFile = File(...)):
    logger.debug('files.put_file(%s)::%s (%s)',
                 file_id, file.filename, file.content_type)
    try:
        data = await file.read()
    finally:
        await file.close()
    result = await db.bin_store.put_async(
        file_id, data, file.content_type, file.filename
    )
    return result.dict(exclude={'data'})


@router.delete('/{file_id}', dependencies=[Depends(access_check)])
async def delete_file(file_id: str):
    logger.debug('files.delete_file(%s)', file_id)
    result = await db.bin_store.delete_async(file_id)
    return result.dict(exclude={'data'})

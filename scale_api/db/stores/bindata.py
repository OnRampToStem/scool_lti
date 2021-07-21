import logging
from typing import List

from scale_api import aio, schemas
from .. import errors
from ..core import SessionLocal, sa
from ..models import BinData

logger = logging.getLogger(__name__)


class BinaryStore:
    """Binary data Repository."""
    def get(self, file_id: str) -> schemas.BinaryFile:
        with SessionLocal() as session:
            entry = session.get(BinData, file_id)
            if not entry:
                raise LookupError(file_id)
            return schemas.BinaryFile.from_orm(entry)

    def put(
            self,
            file_id: str,
            data: bytes,
            content_type: str = 'application/octet-stream',
            name: str = None
    ) -> schemas.BinaryFile:
        try:
            with SessionLocal.begin() as session:
                entry = BinData(
                    id=file_id,
                    data=data,
                    content_type=content_type,
                    name=name,
                )
                session.add(entry)
                session.flush()
                return schemas.BinaryFile.from_orm(entry)
        except errors.IntegrityError:
            with SessionLocal.begin() as session:
                entry = session.get(BinData, file_id)
                if not entry:
                    raise
                logger.info('put_file updating previous entry: %s', entry)
                entry.data = data
                entry.content_type = content_type
                entry.name = name
                session.flush()
                return schemas.BinaryFile.from_orm(entry)

    def delete(self, file_id: str) -> schemas.BinaryFile:
        pass

    get_async = aio.wrap(get)
    put_async = aio.wrap(put)
    delete_async = aio.wrap(delete)

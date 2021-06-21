import logging
import threading
import time

from scale_api import db

logger = logging.getLogger(__name__)

DELAY_HOUR = 60 * 60
DELAY_DAY = DELAY_HOUR * 24


# TODO: use a Task Scheduling library
class Scheduler:

    def __init__(self) -> None:
        self._thread = None
        self._working = False

    def start(self) -> None:
        self._thread = threading.Thread(
            group=None,
            target=self.run,
            name='task_scheduler',
            daemon=True,
        )
        self._working = True
        self._thread.start()

    def stop(self) -> None:
        self._working = False

    def run(self) -> None:
        logger.info('Running Task Scheduler')
        while self._working:
            self.execute(purge_expired_cache_rows)
            time.sleep(DELAY_HOUR)

    def execute(self, func, *args, **kwargs) -> None:
        try:
            func(*args, **kwargs)
        except Exception as exc:
            logger.error('Execute failed [%r]: %s, %s, %s',
                         exc, func, args, kwargs)


def purge_expired_cache_rows() -> None:
    logger.info('Purging expired cache table entries')
    try:
        rows_purged = db.cache_store.purge_expired()
        logger.info('Rows purged: %s', rows_purged)
    except Exception as exc:
        logger.error('CacheStore.purge_expired failed: %r', exc)


task_scheduler = Scheduler()

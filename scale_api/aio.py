"""
Async utilities
"""
import functools
import logging
import typing

import httpx
from starlette.concurrency import run_in_threadpool

from scale_api import app_config

T = typing.TypeVar('T')

logger = logging.getLogger(__name__)

http_client = httpx.AsyncClient(verify=app_config.is_production)


def wrap(fn: typing.Callable[..., T]) -> typing.Callable[..., typing.Awaitable[T]]:
    """Decorator that runs the function in a threadpool.

    Uses the Starlette ``run_in_threadpool`` function to turn a sync function
    into an Awaitable.

    Use as a decorator for a sync function so it can be awaited in an async
    function:

    @aio.wrap
    def my_sync_func(): ...

    async def my_async_func():
        await my_sync_func()
    """
    @functools.wraps(fn)
    async def inner(*args, **kwargs) -> T:
        return await run_in_threadpool(fn, *args, **kwargs)

    return inner

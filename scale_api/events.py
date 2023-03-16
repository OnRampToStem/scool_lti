import asyncio
import concurrent.futures
import contextlib
import logging

from fastapi import FastAPI

from . import aio
from .settings import app_config

logger = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    await on_startup_app(app)
    yield
    await on_shutdown_app(app)


async def on_startup_app(app: FastAPI) -> None:
    """Runs at startup for each web worker process.

    Since most non-async code will be database IO bound, we set our own
    ThreadPoolExecutor with a configured number of workers. We want at
    least ~10 workers, but if using the default executor on a smallish
    EC2 instance would only have on ~5.
    """
    loop = asyncio.get_running_loop()
    logger.info("Starting up in loop [%r]", loop)
    workers = app_config.api.thread_pool_workers
    logger.info("ThreadPoolExecutor(max_workers=%s)", workers)
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="scale_api",
    )
    app.state.thread_pool_executor = executor
    loop = asyncio.get_running_loop()
    loop.set_default_executor(executor)


async def on_shutdown_app(app: FastAPI) -> None:
    """Runs on shutdown for each web worker process.

    Since we manually configured a ThreadPoolExecutor on startup we shut
    it down here along with any other resources that may have been started
    on startup on during execution.
    """
    logger.info("Shutdown event")
    app.state.thread_pool_executor.shutdown()
    await aio.http_client.aclose()


def on_startup_main() -> None:
    """Runs once before any web worker processes are started.

    This code runs before any processing spawning/forking occurs, so no
    threads should be started here or if so they should complete before
    this function ends.

    We use this startup event to create and seed the database for local
    development.
    """
    if app_config.api.is_local:
        import alembic.command
        import alembic.config

        config_file = str(app_config.base_path / "alembic.ini")
        alembic_cfg = alembic.config.Config(config_file)
        alembic_cfg.set_main_option(
            "script_location",
            str(app_config.base_path / "alembic"),
        )
        alembic.command.upgrade(alembic_cfg, "head")

        import scale_api.db.seed

        scale_api.db.seed.main()


def on_shutdown_main() -> None:
    """Runs once before any web worker processes are started."""

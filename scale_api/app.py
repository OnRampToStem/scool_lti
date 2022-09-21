"""
FastAPI main entry point

This modules configures our FastAPI application.
"""
import asyncio
import concurrent.futures
import logging
import sys

from fastapi import FastAPI, Request
from fastapi import __version__ as fastapi_version
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from scale_api import (
    __version__,
    app_config,
    aio,
    db,
    settings,
)
from scale_api.routes import api_router, index_api

logger = logging.getLogger(__name__)

logger.info('Using Environment [%s] file for settings: %s',
            app_config.ENV, app_config.Config.env_file)

logger.info('Is Production: %s', app_config.is_production)

app = FastAPI(
    title='OR2STEM API',
    version=__version__,
    docs_url=f'{app_config.PATH_PREFIX}/docs',
    redoc_url=None,
    openapi_url=f'{app_config.PATH_PREFIX}/openapi.json',
    debug=app_config.DEBUG_APP,
)

logger.info('Adding Session middleware with max age (in secs): %s',
            app_config.SESSION_MAX_AGE)
# Session middleware allows use of ``request.session`` as a dict and is used
# to store SCALE user info. The session cookie is a JWT, so information
# stored is not encrypted (just signed).
app.add_middleware(
    SessionMiddleware,
    secret_key=app_config.SECRET_KEY,
    same_site='None',
    https_only=True,
    max_age=app_config.SESSION_MAX_AGE,
)

logger.info('Adding CORS middleware for origins: %s',
            app_config.BACKEND_CORS_ORIGINS)
# CORS middleware allows for making xhr requests to the API from the
# front-end webapp. This is used mainly for development so that the front-end
# can be run on ``http://localhost:8080`` and able to make calls to the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(u) for u in app_config.BACKEND_CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.middleware('http')
async def log_lti_init_headers(request: Request, call_next):
    response = await call_next(request)
    if response.headers.get('X-LTI-Init'):
        if values := response.headers.getlist('set-cookie'):
            sizes = [len(x) for x in values]
            logger.warning('X-LTI-Init: set-cookie:[%s]: %r -- %r',
                           request.client.host,
                           sizes,
                           values)
            if len(values) != 3:
                logger.error('X-LTI-Init: set-cookie:[%s]: want=[3], got=[%s]',
                             request.client.host, len(values))
    return response


@app.on_event('startup')
async def startup_event():
    """Runs at startup for each web worker process.

    Since most non-async code will be database IO bound, we set our own
    ThreadPoolExecutor with a configured number of workers. We want at
    least ~10 workers, but if using the default executor on a smallish
    EC2 instance would only have on ~5.
    """
    loop = asyncio.get_running_loop()
    logger.info('Starting up in loop [%r]', loop)
    workers = app_config.THREAD_POOL_WORKERS
    logger.info('ThreadPoolExecutor(max_workers=%s)', workers)
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix='scale_api',
    )
    app.state.thread_pool_executor = executor
    loop = asyncio.get_running_loop()
    loop.set_default_executor(executor)


@app.on_event('shutdown')
async def shutdown_event():
    """Runs on shutdown for each web worker process.

    Since we manually configured a ThreadPoolExecutor on startup we shut
    it down here along with any other resources that may have been started
    on startup on during execution.
    """
    logger.info('Shutdown event')
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
    if app_config.ENV == 'local':
        import alembic.command
        import alembic.config

        config_file = str(settings.BASE_PATH / 'alembic.ini')
        alembic_cfg = alembic.config.Config(config_file)
        alembic_cfg.set_main_option('script_location', str(settings.BASE_PATH / 'alembic'))
        alembic.command.upgrade(alembic_cfg, 'head')

        import scale_initdb
        import scale_api.settings

        seed_file = scale_api.settings.BASE_PATH / 'scale_initdb.json'
        if not seed_file.exists():
            seed_file = scale_api.settings.BASE_PATH / 'scale_initdb-example.json'
        scale_initdb.run(seed_file)


def on_shutdown_main() -> None:
    """Runs once before any web worker processes are started."""
    pass


@app.get('/', include_in_schema=False)
@app.get(app_config.PATH_PREFIX, include_in_schema=False)
async def index(request: Request):
    return await index_api(request)


@app.get(f'{app_config.PATH_PREFIX}/lb-status', include_in_schema=False)
async def health_check():
    """Provides a health check endpoint for the Load Balancer."""
    return {
        'app_version': __version__,
        'framework_version': fastapi_version,
        'lang_version': sys.version,
        'environment': app_config.ENV,
        'engine': str(db.engine),
    }


# All routes are defined in ``scale_api.routes``
app.include_router(api_router, prefix=app_config.PATH_PREFIX)


def main() -> None:
    """Runs app in a local development mode.

    Only use for local development testing.
    """
    from pathlib import Path
    import uvicorn

    run_opts: dict[str, int | bool | str] = {
        'port': 8000,
        'reload': True,
        'debug': app_config.DEBUG_APP,
    }

    if app_config.USE_SSL_FOR_APP_RUN_LOCAL:
        cert_path = Path(__file__).parent.parent / 'tests/certs'
        run_opts['port'] = 443
        run_opts['ssl_keyfile'] = f"{cert_path / 'local_ssl_key.pem'}"
        run_opts['ssl_certfile'] = f"{cert_path / 'local_ssl_cert.pem'}"

    on_startup_main()
    uvicorn.run('scale_api.app:app', **run_opts)
    on_shutdown_main()


if __name__ == '__main__':
    main()

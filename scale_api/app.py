import asyncio
import concurrent.futures
import logging
import sys

from fastapi import FastAPI, Request
from fastapi import __version__ as fastapi_version
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from scale_api import (
    __version__,
    app_config,
    aio,
    db,
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
app.add_middleware(
    SessionMiddleware,
    secret_key=app_config.SECRET_KEY,
    same_site='None',
    https_only=True,
    max_age=app_config.SESSION_MAX_AGE,
)

logger.info('Adding CORS middleware for origins: %s',
            app_config.BACKEND_CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(u) for u in app_config.BACKEND_CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.on_event('startup')
async def startup_event():
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
    logger.info('Shutdown event')
    app.state.thread_pool_executor.shutdown()
    await aio.http_client.aclose()


def on_startup_main() -> None:
    if app_config.ENV == 'local':
        import scale_initdb
        import scale_api.settings

        seed_file = scale_api.settings.BASE_PATH / 'scale_initdb.json'
        if not seed_file.exists():
            seed_file = scale_api.settings.BASE_PATH / 'scale_initdb-example.json'
        scale_initdb.run(seed_file)


def on_shutdown_main() -> None:
    pass


@app.get('/', include_in_schema=False)
@app.get(app_config.PATH_PREFIX, include_in_schema=False)
async def index(request: Request):
    return await index_api(request)


@app.get(f'{app_config.PATH_PREFIX}/lb-status', include_in_schema=False)
async def health_check():
    return {
        'app_version': __version__,
        'framework_version': fastapi_version,
        'lang_version': sys.version,
        'environment': app_config.ENV,
        'engine': str(db.engine),
    }


app.include_router(api_router, prefix=app_config.PATH_PREFIX)


def main() -> None:
    """Runs app in a local development mode.

    Only use for local development testing.
    """
    from pathlib import Path
    import uvicorn

    run_opts = {
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

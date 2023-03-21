import logging
import os

from gunicorn import glogging

from scale_api.settings import app_config

MAX_WORKERS = os.cpu_count() * 2
WORKER_COUNT = int(os.getenv("WEB_CONCURRENCY", f"{MAX_WORKERS}"))


class HealthCheckFilter(logging.Filter):
    def filter(self, record):  # noqa: A003
        prefix = app_config.api.path_prefix
        return f"GET {prefix}/lb-status" not in record.getMessage()


class CustomGunicornLogger(glogging.Logger):
    def setup(self, cfg):
        super().setup(cfg)
        logger = logging.getLogger("uvicorn.access")
        logger.addFilter(HealthCheckFilter())


def on_starting(server):
    import scale_api.events

    logging.warning("on_starting(%r)", server)
    scale_api.events.on_startup_main()


def on_exit(server):
    import scale_api.events

    logging.warning("on_exit(%r)", server)
    scale_api.events.on_shutdown_main()


accesslog = "-"
access_log_format = (
    '%(t)s %({x-forwarded-for}i)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'
)
errorlog = "-"
logger_class = CustomGunicornLogger
logconfig_dict = app_config.log_config
worker_tmp_dir = "/dev/shm"  # noqa: S108
forwarded_allow_ips = "*"
proxy_allow_ips = "*"
bind = ":8000"
worker_class = "uvicorn.workers.UvicornWorker"
# Start at least 2 but no more than 8 workers
workers = max(2, min(8, WORKER_COUNT))
# Increase beyond the default of 30 due to time it takes to load users
timeout = 180

import logging
import os

from gunicorn import glogging

import scale_api

WORKER_COUNT = (os.cpu_count() * 2) + 1


class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        return 'GET /lb-status' not in record.getMessage()


class CustomGunicornLogger(glogging.Logger):
    def setup(self, cfg):
        super().setup(cfg)
        logger = logging.getLogger("gunicorn.access")
        logger.addFilter(HealthCheckFilter())


def on_starting(server):
    import scale_api.app
    scale_api.app.on_startup_main()


def on_exit(server):
    import scale_api.app
    scale_api.app.on_shutdown_main()


accesslog = '-'
access_log_format = '%(t)s %({x-forwarded-for}i)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'
errorlog = '-'
logger_class = CustomGunicornLogger
logconfig_dict = scale_api.LOGGING
worker_tmp_dir = '/dev/shm'
forwarded_allow_ips = '*'
proxy_allow_ips = '*'
bind = ':8000'
worker_class = 'uvicorn.workers.UvicornWorker'
workers = min(2, WORKER_COUNT)
# keyfile = "/etc/ssl/key.pem"
# certfile = "/etc/ssl/cert.pem"

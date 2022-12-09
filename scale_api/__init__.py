"""
SCALE API (OR2STEM)
"""
import logging.config
import os

from . import settings

__version__ = '22.12.9'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'basic': {
            'format': '%(asctime)s[%(levelname)s]%(name)s: %(message)s',
            'datefmt': '%Y-%m-%dT%H:%M:%S',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'basic',
            'stream': 'ext://sys.stdout',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': os.getenv('SCALE_LOG_LEVEL', 'WARNING'),
        },
        'scale_api': {
            'level': os.getenv('SCALE_LOG_LEVEL_APP', 'INFO'),
        },
    },
}

logging.config.dictConfig(LOGGING)

app_config = settings.ScaleSettings()

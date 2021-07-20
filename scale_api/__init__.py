"""
SCALE API (OR2STEM)
"""
import logging.config
import os

from . import settings

__version__ = '21.7.21'

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
        'uvicorn': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'scale_api': {
            'handlers': ['console'],
            'level': os.getenv('SCALE_LOG_LEVEL_APP', 'INFO'),
            'propagate': False,
        },
    },
}

logging.config.dictConfig(LOGGING)

app_config = settings.ScaleSettings()

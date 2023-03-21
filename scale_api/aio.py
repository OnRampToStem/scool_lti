"""
Async utilities
"""
import httpx

from .settings import app_config

http_client = httpx.AsyncClient(verify=app_config.api.is_production)

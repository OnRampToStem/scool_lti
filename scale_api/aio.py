"""
Async utilities
"""
import httpx

from . import settings

http_client = httpx.AsyncClient(verify=settings.api.is_production)

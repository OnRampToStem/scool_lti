"""
SCALE API Database

This package defines the models and repositories (stores) used to store data
for this application.
"""
from .core import SessionLocal, engine
from .stores import CacheStore, ScaleStore

store = ScaleStore()
cache_store = CacheStore()

__all__ = [
    "CacheStore",
    "ScaleStore",
    "SessionLocal",
    "cache_store",
    "engine",
    "store",
]

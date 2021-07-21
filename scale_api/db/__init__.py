"""
SCALE API Database

This package defines the models and repositories (stores) used to store data
for this application.
"""
from .core import (
    Base,
    SessionLocal,
    engine,
)

from .stores import (
    CacheStore,
    MessageStore,
    ScaleStore,
    UserStore,
)

store = ScaleStore()
cache_store = CacheStore()
message_store = MessageStore()
user_store = UserStore()

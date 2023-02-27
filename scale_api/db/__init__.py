"""
SCALE API Database

This package defines the models and repositories (stores) used to store data
for this application.
"""
from .core import (
    SessionLocal,
    engine,
)

from .stores import (
    BinaryStore,
    CacheStore,
    MessageStore,
    ScaleStore,
    UserStore,
)

store = ScaleStore()
bin_store = BinaryStore()
cache_store = CacheStore()
message_store = MessageStore()
user_store = UserStore()

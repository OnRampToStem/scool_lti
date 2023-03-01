"""
SCALE API Database

This package defines the models and repositories (stores) used to store data
for this application.
"""
from .core import (
    SessionLocal as SessionLocal,
    engine as engine,
)

from .stores import (
    BinaryStore as BinaryStore,
    CacheStore as CacheStore,
    MessageStore as MessageStore,
    ScaleStore as ScaleStore,
    UserStore as UserStore,
)

store = ScaleStore()
bin_store = BinaryStore()
cache_store = CacheStore()
message_store = MessageStore()
user_store = UserStore()

"""
SCALE API Database

This package defines the models and repositories (stores) used to store data
for this application.
"""
from .core import (
    SessionLocal as SessionLocal,
)
from .core import (
    engine as engine,
)
from .stores import (
    BinaryStore as BinaryStore,
)
from .stores import (
    CacheStore as CacheStore,
)
from .stores import (
    MessageStore as MessageStore,
)
from .stores import (
    ScaleStore as ScaleStore,
)
from .stores import (
    UserStore as UserStore,
)

store = ScaleStore()
bin_store = BinaryStore()
cache_store = CacheStore()
message_store = MessageStore()
user_store = UserStore()

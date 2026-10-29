import redis as redis_lib
from app.core.config import settings
from app.services.redis_store import RedisTokenStore

_pool = redis_lib.ConnectionPool(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    password=settings.REDIS_PASSWORD or None,
    db=settings.REDIS_DB,
    decode_responses=True,
)


def get_redis_store() -> RedisTokenStore:
    client = redis_lib.Redis(connection_pool=_pool)
    return RedisTokenStore(client)

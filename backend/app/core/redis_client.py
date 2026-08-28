import redis.asyncio as redis
from app.core.config import settings

redis_client = None

async def get_redis():
    global redis_client
    if not redis_client:
        url = getattr(settings, "redis_url", "redis://localhost:6379/0")
        redis_client = redis.from_url(url, decode_responses=True)
    return redis_client

import redis.asyncio as redis
from app.core.config import settings
import logging

redis_client = None
logger = logging.getLogger(__name__)

async def get_redis():
    global redis_client
    if not redis_client:
        url = getattr(settings, "redis_url", "redis://redis:6379/0")
        try:
            temp_client = redis.from_url(url, decode_responses=True)
            await temp_client.ping()
            redis_client = temp_client
        except Exception as e:
            logger.warning(f"Failed to connect to redis at {url}, falling back to localhost. Error: {e}")
            fallback_url = url.replace("redis://redis:6379", "redis://localhost:6379")
            redis_client = redis.from_url(fallback_url, decode_responses=True)
    return redis_client

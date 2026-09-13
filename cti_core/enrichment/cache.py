"""Redis-backed caching layer with in-memory fallback for enrichment API rate-limiting."""

import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)


class EnrichmentCache:
    """Caching service providing TTL-backed cache across Redis and in-memory store."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis_client = None
        self._memory_cache: dict[str, tuple[str, float]] = {}
        self._redis_tested = False
        self._redis_available = False

    async def _get_redis(self):
        if not self._redis_tested:
            self._redis_tested = True
            try:
                import redis.asyncio as aioredis
                client = aioredis.from_url(
                    self.redis_url,
                    socket_connect_timeout=1.0,
                    decode_responses=True,
                )
                await client.ping()
                self._redis_client = client
                self._redis_available = True
                logger.info("Connected to Redis cache at %s", self.redis_url)
            except Exception:
                logger.info("Redis unavailable; defaulting to in-memory TTL enrichment cache.")
                self._redis_available = False
        return self._redis_client if self._redis_available else None

    async def get(self, key: str) -> Optional[Any]:
        """Retrieve item from Redis or memory cache."""
        redis_conn = await self._get_redis()
        if redis_conn:
            try:
                data = await redis_conn.get(key)
                if data:
                    return json.loads(data)
            except Exception as exc:
                logger.debug("Redis get error: %s; falling back to memory.", exc)

        # In-memory fallback
        if key in self._memory_cache:
            serialized, expiry = self._memory_cache[key]
            if time.time() < expiry:
                return json.loads(serialized)
            else:
                del self._memory_cache[key]
        return None

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        """Store item in cache with expiration in seconds (default 24 hours)."""
        serialized = json.dumps(value)
        redis_conn = await self._get_redis()
        if redis_conn:
            try:
                await redis_conn.setex(key, ttl_seconds, serialized)
                return
            except Exception as exc:
                logger.debug("Redis set error: %s; falling back to memory.", exc)

        # In-memory fallback
        self._memory_cache[key] = (serialized, time.time() + ttl_seconds)


# Global singleton cache instance
global_cache = EnrichmentCache()

"""Abstract base collector with asynchronous rate limiting, jittered exponential backoff, and offline fallback."""

import asyncio
import logging
import os
import random
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract collector for ingesting indicators from external or mock threat intelligence feeds."""

    def __init__(
        self,
        name: str,
        source_weight: float = 0.8,
        rate_limit_per_second: float = 2.0,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        timeout: float = 15.0,
    ):
        self.name = name
        self.source_weight = source_weight
        self.rate_limit_per_second = rate_limit_per_second
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max(1, int(rate_limit_per_second)))
        self.offline_mode = os.getenv("OFFLINE_MODE", "false").lower() in ("true", "1", "yes")

    async def fetch_with_retry(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
    ) -> Optional[httpx.Response]:
        """Execute async HTTP request with rate limiting and exponential backoff retries."""
        async with self._semaphore:
            attempt = 0
            while attempt < self.max_retries:
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.request(
                            method=method,
                            url=url,
                            headers=headers,
                            params=params,
                            json=json_data,
                        )
                        # Retry on rate limiting or server errors
                        if response.status_code in (429, 500, 502, 503, 504):
                            response.raise_for_status()
                        return response
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    attempt += 1
                    sleep_time = (self.backoff_factor * (2 ** (attempt - 1))) + random.uniform(0.1, 0.5)
                    logger.warning(
                        "[%s] Request to %s failed (attempt %d/%d): %s. Retrying in %.2fs...",
                        self.name,
                        url,
                        attempt,
                        self.max_retries,
                        str(exc),
                        sleep_time,
                    )
                    if attempt >= self.max_retries:
                        logger.error("[%s] Max retries reached for %s", self.name, url)
                        return None
                    await asyncio.sleep(sleep_time)
        return None

    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect and return raw indicator records from the threat feed."""
        pass

    @abstractmethod
    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic offline feed data when network or API credentials are unavailable."""
        pass

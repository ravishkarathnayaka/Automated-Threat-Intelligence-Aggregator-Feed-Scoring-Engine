"""Security middleware providing optional API key authorization and sliding-window rate limiting."""

import os
import time
from collections import defaultdict
from typing import Any, Dict, List, Set

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

# Public endpoints exempted from API key authentication
PUBLIC_PATHS: Set[str] = {
    "/",
    "/health",
    "/api/health",
    "/api/v1/health",
    "/v1/health",
    "/api",
    "/api/status",
    "/status",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/styles.css",
    "/app.js",
    "/favicon.ico",
}


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Protects internal ingestion and export endpoints when API_KEY is configured."""

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        self.api_key: str = os.getenv("API_KEY", "")
        self.enforce: bool = os.getenv("ENFORCE_API_KEY", "false").lower() in ("true", "1", "yes")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.enforce or not self.api_key:
            return await call_next(request)

        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith(("/static", "/docs", "/redoc")):
            return await call_next(request)

        # Check X-API-Key header or Bearer token
        provided_key = request.headers.get("X-API-Key")
        if not provided_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                provided_key = auth_header.split(" ", 1)[1].strip()

        if provided_key != self.api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Invalid or missing API key."},
            )

        return await call_next(request)


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """In-memory sliding window rate limiter per client IP address."""

    def __init__(self, app: Any, max_requests_per_minute: int = 240) -> None:
        super().__init__(app)
        self.max_requests = max_requests_per_minute
        self.window_seconds = 60.0
        self.request_history: Dict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Exempt static assets and health probes
        path = request.url.path
        if path in ("/health", "/api/v1/health", "/styles.css", "/app.js"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()

        # Clean history older than window
        timestamps = self.request_history[client_ip]
        self.request_history[client_ip] = [t for t in timestamps if now - t < self.window_seconds]

        if len(self.request_history[client_ip]) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - self.request_history[client_ip][0]))
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests: Rate limit exceeded."},
                headers={"Retry-After": str(max(1, retry_after))},
            )

        self.request_history[client_ip].append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.max_requests - len(self.request_history[client_ip])))
        return response

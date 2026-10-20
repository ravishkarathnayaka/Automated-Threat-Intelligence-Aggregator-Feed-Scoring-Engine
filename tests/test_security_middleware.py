"""Unit tests verifying API key authorization and sliding window rate limiting."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app
from api.middleware.security import APIKeyAuthMiddleware, RateLimiterMiddleware


@pytest.mark.asyncio
async def test_public_endpoints_accessible_without_auth():
    """Verify health, status, and documentation endpoints remain public."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Health check
        res_health = await client.get("/health")
        assert res_health.status_code == 200

        # API status
        res_status = await client.get("/api/status")
        assert res_status.status_code == 200

        # Documentation
        res_docs = await client.get("/docs")
        assert res_docs.status_code == 200


@pytest.mark.asyncio
async def test_rate_limiter_headers():
    """Verify rate limit headers (Limit, Remaining) are populated on HTTP responses."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/status")
        assert response.status_code == 200
        assert "x-ratelimit-limit" in response.headers
        assert "x-ratelimit-remaining" in response.headers


@pytest.mark.asyncio
async def test_rate_limiter_rejection():
    """Verify rate limiter middleware triggers 429 Too Many Requests when threshold exceeded."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def dummy_endpoint(request):
        return PlainTextResponse("OK")

    test_app = Starlette(routes=[Route("/test-rate", dummy_endpoint)])
    test_app.add_middleware(RateLimiterMiddleware, max_requests_per_minute=3)

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        # First 3 requests succeed
        for _ in range(3):
            res = await client.get("/test-rate")
            assert res.status_code == 200

        # 4th request must be rejected with 429
        rejected = await client.get("/test-rate")
        assert rejected.status_code == 429
        assert "Retry-After" in rejected.headers


@pytest.mark.asyncio
async def test_api_key_enforcement(monkeypatch):
    """Verify API key authentication enforcement when enabled."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    monkeypatch.setenv("API_KEY", "super-secret-token-123")
    monkeypatch.setenv("ENFORCE_API_KEY", "true")

    async def protected_endpoint(request):
        return PlainTextResponse("Secret Threat Data")

    test_app = Starlette(routes=[Route("/protected/export", protected_endpoint)])
    test_app.add_middleware(APIKeyAuthMiddleware)

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        # Missing key -> 401
        res_no_key = await client.get("/protected/export")
        assert res_no_key.status_code == 401

        # Valid X-API-Key header -> 200
        res_valid = await client.get("/protected/export", headers={"X-API-Key": "super-secret-token-123"})
        assert res_valid.status_code == 200
        assert res_valid.text == "Secret Threat Data"

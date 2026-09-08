from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    """Small local rate limiter for prototype hardening.

    It protects login, MFA, upload, and general API routes from repeated automated
    requests during demonstrations. For production, replace this with Redis-backed
    rate limiting at the API gateway/reverse proxy layer.
    """

    def __init__(self, app):
        super().__init__(app)
        self._buckets: dict[str, Deque[float]] = defaultdict(deque)

    @staticmethod
    def _client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _limit_for_path(path: str) -> int:
        if path.startswith("/api/auth/"):
            return settings.rate_limit_auth_requests
        if path.startswith("/api/files/send"):
            return settings.rate_limit_upload_requests
        return settings.rate_limit_general_requests

    async def dispatch(self, request: Request, call_next):
        if not settings.rate_limit_enabled or not request.url.path.startswith("/api/"):
            return await call_next(request)

        now = time.time()
        window = settings.rate_limit_window_seconds
        ip = self._client_ip(request)
        limit = self._limit_for_path(request.url.path)
        key = f"{ip}:{request.url.path.split('?')[0]}"
        bucket = self._buckets[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()

        if len(bucket) >= limit:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Too many requests. Try again after {window} seconds.",
                    "scope": "rate_limit",
                },
            )
        bucket.append(now)
        return await call_next(request)

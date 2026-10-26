"""Rate limiting middleware using sliding window (D7).

Per-user rate and token limits. Reuses the idea of a sliding-window
limiter but with a fresh implementation.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from fastapi import HTTPException, Request, status

from src.core.config import get_settings

import structlog

logger = structlog.get_logger(__name__)


class SlidingWindowRateLimiter:
    """Sliding window rate limiter for per-user request throttling.

    Tracks request timestamps in a sliding window and rejects
    requests that exceed the configured limit.
    """

    def __init__(self) -> None:
        self._request_windows: dict[str, list[float]] = defaultdict(list)
        self._token_counts: dict[str, int] = defaultdict(int)
        self._window_start: dict[str, float] = {}

    def _cleanup_window(self, user_id: str, window_seconds: float = 60.0) -> None:
        """Remove timestamps outside the sliding window."""
        now = time.time()
        cutoff = now - window_seconds
        self._request_windows[user_id] = [
            ts for ts in self._request_windows[user_id] if ts > cutoff
        ]

    def check_rate_limit(self, user_id: str) -> None:
        """Check if the user has exceeded their rate limit.

        Raises HTTPException 429 if rate limit exceeded.
        """
        settings = get_settings()
        self._cleanup_window(user_id)

        if len(self._request_windows[user_id]) >= settings.rate_limit.requests_per_minute:
            logger.warning("rate_limit_exceeded", user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
            )

        self._request_windows[user_id].append(time.time())

    def check_token_limit(self, user_id: str, tokens: int) -> None:
        """Check if user has exceeded their token budget.

        Resets every minute.
        """
        settings = get_settings()
        now = time.time()

        # Reset counter every minute
        if user_id not in self._window_start or now - self._window_start[user_id] > 60:
            self._window_start[user_id] = now
            self._token_counts[user_id] = 0

        if self._token_counts[user_id] + tokens > settings.rate_limit.tokens_per_minute:
            logger.warning("token_limit_exceeded", user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Token limit exceeded. Please try again later.",
            )

        self._token_counts[user_id] += tokens

    def record_tokens(self, user_id: str, tokens: int) -> None:
        """Record token usage for a user."""
        self._token_counts[user_id] = self._token_counts.get(user_id, 0) + tokens


# Singleton instance
rate_limiter = SlidingWindowRateLimiter()

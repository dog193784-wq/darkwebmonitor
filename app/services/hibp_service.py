"""HIBP breach intelligence service layer.

This service implements the password range-query workflow based on HIBP's
k-anonymity model:
1) Hash password locally (SHA-1 uppercase).
2) Send only the 5-character prefix to HIBP.
3) Match the 35-character suffix locally.

Why this architecture preserves privacy:
- Neither plaintext passwords nor full hashes leave the application boundary.
- Cached range responses are keyed by prefix only, reducing repeated outbound
  requests while keeping secret exposure minimal.
"""

from __future__ import annotations

from typing import Final

import httpx
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.security import hash_and_split_for_hibp

settings = get_settings()

HIBP_PADDING_HEADER: Final[dict[str, str]] = {"Add-Padding": "true"}


class HIBPServiceError(RuntimeError):
    """Raised when HIBP cannot be safely queried or parsed."""


_redis_client: Redis | None = None


def get_redis_client() -> Redis:
    """Return a singleton async Redis client.

    A process-scoped client avoids repeated connection setup and improves
    throughput under API load.
    """

    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def _parse_hibp_range_response(range_response: str, expected_suffix: str) -> int:
    """Find breach count for ``expected_suffix`` from HIBP range response body.

    The response body is line-delimited in ``<SUFFIX>:<COUNT>`` format.
    Parsing is done locally so suffix values never leave this process.
    """

    for line in range_response.splitlines():
        if not line:
            continue
        suffix, _, count_text = line.partition(":")
        if suffix.strip().upper() == expected_suffix:
            return int(count_text.strip() or "0")
    return 0


async def check_password_breach(password: str) -> dict[str, int | bool]:
    """Check whether a password appears in known breach datasets.

    Raises:
        HIBPServiceError: If network timeout, remote service failure, or
            response parsing issues prevent a reliable result.
    """

    prefix, suffix = hash_and_split_for_hibp(password)
    redis_client = get_redis_client()
    cache_key = f"hibp:range:{prefix}"

    try:
        cached_response = await redis_client.get(cache_key)
        if cached_response is None:
            endpoint = f"{settings.hibp_base_url}/range/{prefix}"
            async with httpx.AsyncClient(timeout=settings.hibp_timeout_seconds) as client:
                response = await client.get(endpoint, headers=HIBP_PADDING_HEADER)
                response.raise_for_status()
                cached_response = response.text
            await redis_client.set(cache_key, cached_response, ex=settings.hibp_cache_ttl_seconds)

        count = _parse_hibp_range_response(cached_response, suffix)
        return {"breached": count > 0, "count": count}
    except httpx.TimeoutException as exc:
        raise HIBPServiceError("HIBP request timed out.") from exc
    except httpx.HTTPStatusError as exc:
        raise HIBPServiceError("HIBP returned an unexpected HTTP status.") from exc
    except httpx.RequestError as exc:
        raise HIBPServiceError("Unable to reach HIBP service.") from exc
    except ValueError as exc:
        raise HIBPServiceError("Unable to parse HIBP response payload.") from exc

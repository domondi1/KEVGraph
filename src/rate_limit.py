"""Rate-limited, cached HTTP helpers with automatic retry on 429 / 5xx.

Every public function here honours the disk cache (src.cache) so
repeated pipeline runs are near-instant for previously fetched data.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from . import cache, config

log = logging.getLogger(__name__)

# ── Per-domain token-bucket rate limiters ────────────────────────────────────

class _TokenBucket:
    """Simple thread-safe token-bucket limiter."""

    def __init__(self, rate: float):
        self._rate = rate
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens < 1:
                sleep = (1 - self._tokens) / self._rate
                time.sleep(sleep)
                self._tokens = 0
            else:
                self._tokens -= 1


_buckets: dict[str, _TokenBucket] = {
    "github": _TokenBucket(config.GITHUB_REQ_PER_SEC),
    "osv": _TokenBucket(50),          # OSV is generous
    "npm": _TokenBucket(config.NPM_REQ_PER_SEC),
    "deps_dev": _TokenBucket(config.DEPS_DEV_REQ_PER_SEC),
}


def _bucket_for(url: str) -> _TokenBucket | None:
    if "github.com" in url or "githubusercontent.com" in url:
        return _buckets["github"]
    if "osv.dev" in url:
        return _buckets["osv"]
    if "registry.npmjs.org" in url:
        return _buckets["npm"]
    if "deps.dev" in url:
        return _buckets["deps_dev"]
    return None


# ── Retry-decorated low-level request ────────────────────────────────────────

class RateLimitError(Exception):
    """Raised when an API returns 429 so tenacity can retry."""


class ServerError(Exception):
    """Raised on 5xx so tenacity can retry."""


_session = requests.Session()


@retry(
    retry=retry_if_exception_type((RateLimitError, ServerError)),
    wait=wait_exponential(multiplier=2, min=2, max=120),
    stop=stop_after_attempt(config.MAX_RETRIES),
    reraise=True,
)
def _raw_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    bucket = _bucket_for(url)
    if bucket:
        bucket.acquire()
    resp = _session.request(method, url, timeout=config.HTTP_TIMEOUT, **kwargs)
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "60"))
        log.warning("429 from %s – backing off %ds", url, retry_after)
        time.sleep(retry_after)
        raise RateLimitError(url)
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        reset_ts = int(resp.headers.get("X-RateLimit-Reset", "0"))
        wait = max(reset_ts - int(time.time()), 5)
        log.warning("GitHub rate-limit hit – sleeping %ds", wait)
        time.sleep(wait)
        raise RateLimitError(url)
    if resp.status_code >= 500:
        raise ServerError(f"{resp.status_code} from {url}")
    return resp


# ── Public helpers ───────────────────────────────────────────────────────────

def github_headers() -> dict[str, str]:
    h: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    return h


def get_json(url: str, *, headers: dict | None = None, use_cache: bool = True) -> Any:
    """GET a URL, return parsed JSON. Cached on disk."""
    if use_cache:
        hit = cache.get("GET", url)
        if hit is not None:
            return hit
    resp = _raw_request("GET", url, headers=headers or {})
    resp.raise_for_status()
    data = resp.json()
    if use_cache:
        cache.put("GET", url, data)
    return data


def post_json(
    url: str,
    body: Any,
    *,
    headers: dict | None = None,
    use_cache: bool = True,
) -> Any:
    """POST JSON body, return parsed response. Cached on (url, body)."""
    if use_cache:
        hit = cache.get("POST", url, body)
        if hit is not None:
            return hit
    resp = _raw_request("POST", url, json=body, headers=headers or {})
    resp.raise_for_status()
    data = resp.json()
    if use_cache:
        cache.put("POST", url, data, body=body)
    return data


def get_text(url: str, *, headers: dict | None = None) -> str:
    """GET a URL, return raw text (not cached by default)."""
    resp = _raw_request("GET", url, headers=headers or {})
    resp.raise_for_status()
    return resp.text

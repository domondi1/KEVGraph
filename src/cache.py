"""Transparent disk-cache for HTTP API responses.

Cache key = SHA-256 of (method, url, sorted-body).  Files older than
CACHE_TTL_HOURS are treated as stale and re-fetched.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from . import config


def _cache_key(method: str, url: str, body: Any = None) -> str:
    blob = f"{method}\n{url}\n{json.dumps(body, sort_keys=True) if body else ''}"
    return hashlib.sha256(blob.encode()).hexdigest()


def _cache_path(key: str) -> Path:
    # two-level fan-out to avoid mega-directories
    return config.CACHE_DIR / key[:2] / f"{key}.json"


def get(method: str, url: str, body: Any = None) -> dict | list | None:
    """Return cached JSON payload or None if miss / stale."""
    path = _cache_path(_cache_key(method, url, body))
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    ts = data.get("_ts", 0)
    if (time.time() - ts) > config.CACHE_TTL_HOURS * 3600:
        return None
    return data.get("payload")


def put(method: str, url: str, payload: Any, body: Any = None) -> None:
    """Persist a JSON-serialisable payload to the disk cache."""
    path = _cache_path(_cache_key(method, url, body))
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"_ts": time.time(), "payload": payload}
    path.write_text(json.dumps(data, separators=(",", ":")))


def clear_all() -> int:
    """Remove every cached file. Returns count deleted."""
    n = 0
    for p in config.CACHE_DIR.rglob("*.json"):
        p.unlink()
        n += 1
    return n

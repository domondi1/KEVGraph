"""Central configuration for the KEVGraph pipeline."""

from __future__ import annotations

import os
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
CACHE_DIR = DATA_DIR / "cached_api"
LOCKFILE_DIR = DATA_DIR / "lockfiles"
GRAPH_DIR = DATA_DIR / "graphs"
PLOT_DIR = DATA_DIR / "plots"
MANIFEST_CSV = DATA_DIR / "manifest.csv"
RESULTS_CSV = DATA_DIR / "results.csv"

for _d in (CACHE_DIR, LOCKFILE_DIR, GRAPH_DIR, PLOT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── GitHub ───────────────────────────────────────────────────────────────────
GITHUB_TOKEN: str | None = os.environ.get("GITHUB_TOKEN")
GITHUB_API = "https://api.github.com"
TARGET_N_REPOS = int(os.environ.get("KEVGRAPH_N_REPOS", "5000"))

# ── Public API endpoints ─────────────────────────────────────────────────────
OSV_API = "https://api.osv.dev/v1"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEPS_DEV_API = "https://api.deps.dev/v3alpha"
NPM_REGISTRY = "https://registry.npmjs.org"

# ── Rate-limit / retry knobs ────────────────────────────────────────────────
GITHUB_REQ_PER_SEC = 8          # stay well under 5000/hr authenticated
OSV_BATCH_SIZE = 1000           # OSV querybatch endpoint max
NPM_REQ_PER_SEC = 15
DEPS_DEV_REQ_PER_SEC = 10
HTTP_TIMEOUT = 30               # seconds
MAX_RETRIES = 5
CACHE_TTL_HOURS = 72            # how long cached API responses stay fresh

# ── Pipeline tuning ──────────────────────────────────────────────────────────
MIN_DEPS_PER_LOCKFILE = 10      # skip trivially small lockfiles
MAX_LOCKFILE_SIZE_MB = 50       # skip absurdly large lockfiles

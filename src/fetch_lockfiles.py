"""Stage 2: Download package-lock.json for every repo in manifest.csv.

Each lockfile is saved to  data/lockfiles/<owner>__<repo>.json
(double-underscore separates owner and repo to avoid nested dirs).

Oversized files (>MAX_LOCKFILE_SIZE_MB) and 404s are logged and skipped.

Usage:
    python -m src.fetch_lockfiles
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from urllib.parse import quote

from tqdm import tqdm

from . import config
from .rate_limit import _raw_request, github_headers

log = logging.getLogger(__name__)


def _lockfile_dest(repo_full_name: str) -> Path:
    safe = repo_full_name.replace("/", "__")
    return config.LOCKFILE_DIR / f"{safe}.json"


def download_one(repo_full_name: str, branch: str, lockfile_path: str) -> Path | None:
    """Download a single lockfile; return dest Path on success, None on skip.

    Reuses the on-disk cache (dest file) so repeated calls are free.
    Safe to call from any stage that needs an ad-hoc lockfile fetch.
    """
    dest = _lockfile_dest(repo_full_name)
    if dest.exists() and dest.stat().st_size > 0:
        return dest

    raw_url = (
        f"https://raw.githubusercontent.com/{quote(repo_full_name, safe='/')}/"
        f"{quote(branch)}/{quote(lockfile_path, safe='/')}"
    )
    try:
        resp = _raw_request("GET", raw_url, headers=github_headers())
        if resp.status_code == 404:
            log.debug("404 for %s", repo_full_name)
            return None
        resp.raise_for_status()
        size_mb = len(resp.content) / (1024 * 1024)
        if size_mb > config.MAX_LOCKFILE_SIZE_MB:
            log.info("Skipping %s (%.1f MB)", repo_full_name, size_mb)
            return None
        dest.write_bytes(resp.content)
        return dest
    except Exception as exc:
        log.warning("Failed %s: %s", repo_full_name, exc)
        return None


def fetch_lockfiles() -> int:
    """Download lockfiles listed in manifest.csv. Returns count fetched."""
    if not config.MANIFEST_CSV.exists():
        raise FileNotFoundError(
            f"{config.MANIFEST_CSV} not found – run collect_repos first."
        )

    with open(config.MANIFEST_CSV) as fh:
        rows = list(csv.DictReader(fh))

    fetched = 0
    skipped = 0
    pbar = tqdm(rows, desc="Fetching lockfiles", unit="file")
    for row in pbar:
        repo = row["repo_full_name"]
        branch = row.get("default_branch", "main")
        lockpath = row.get("lockfile_path", "package-lock.json")
        result = download_one(repo, branch, lockpath)
        if result is not None:
            fetched += 1
        else:
            skipped += 1

    log.info("Fetched %d lockfiles, skipped %d", fetched, skipped)
    return fetched


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    fetch_lockfiles()


if __name__ == "__main__":
    main()

"""Stage 1: Discover GitHub repos that contain a package-lock.json.

Strategy:
  - Use the GitHub Code Search API to find files named package-lock.json.
  - GitHub code-search paginates up to 1000 results per query, so we shard
    by repo-star buckets and file-size ranges to maximise unique repos.
  - Deduplicate on (owner/repo).
  - Write manifest.csv with columns: repo_full_name, default_branch, stars,
    lockfile_path, collected_at.

Usage:
    python -m src.collect_repos          # collects TARGET_N_REPOS repos
    python -m src.collect_repos --n 500  # override target
    python -m src.collect_repos --curated data/curated_repos.txt  # bypass search
"""

from __future__ import annotations

import argparse
import csv
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

from . import config
from .rate_limit import get_json, github_headers

log = logging.getLogger(__name__)

# Star-bucket boundaries used to shard code-search queries (each query
# returns at most 1000 results; sharding by stars lets us reach >10k repos).
_STAR_RANGES = [
    "0..10",
    "11..50",
    "51..200",
    "201..1000",
    "1001..5000",
    "5001..50000",
    ">=50001",
]


def _is_root_lockfile(path: str) -> bool:
    """Return True only for paths that are exactly the lockfile name or end with /name."""
    return path == "package-lock.json" or path.endswith("/package-lock.json")


def _search_page(query: str, page: int) -> dict:
    url = (
        f"{config.GITHUB_API}/search/code"
        f"?q={query}&per_page=100&page={page}"
    )
    return get_json(url, headers=github_headers())


def _collect_from_bucket(star_range: str, seen: set[str], target: int) -> list[dict]:
    """Search one star bucket, return list of repo records."""
    query = f"filename:package-lock.json+in:path+stars:{star_range}"
    rows: list[dict] = []
    page = 1
    while page <= 10 and len(seen) < target:  # max 10 pages per bucket
        try:
            data = _search_page(query, page)
        except Exception as exc:
            log.warning("Search failed for stars:%s page %d: %s", star_range, page, exc)
            break
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            if not _is_root_lockfile(item["path"]):
                continue
            repo = item["repository"]
            full_name = repo["full_name"]
            if full_name in seen:
                continue
            seen.add(full_name)
            rows.append(
                {
                    "repo_full_name": full_name,
                    "default_branch": repo.get("default_branch", "main"),
                    "stars": repo.get("stargazers_count", 0),
                    "lockfile_path": item["path"],
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        page += 1
        if data.get("incomplete_results"):
            log.info("Incomplete results for stars:%s page %d", star_range, page)
    return rows


def collect_repos(target_n: int = config.TARGET_N_REPOS) -> list[dict]:
    """Main entry: collect up to *target_n* unique repos."""
    if not config.GITHUB_TOKEN:
        raise EnvironmentError(
            "GITHUB_TOKEN env var is required for code search. "
            "Create a classic PAT with public_repo scope."
        )

    seen: set[str] = set()
    all_rows: list[dict] = []

    pbar = tqdm(total=target_n, desc="Collecting repos", unit="repo")
    for bucket in _STAR_RANGES:
        if len(seen) >= target_n:
            break
        rows = _collect_from_bucket(bucket, seen, target_n)
        all_rows.extend(rows)
        pbar.update(len(rows))
    pbar.close()

    # ── Supplement with explicit search if still short ────────────────────
    # Use topic / language filters to widen the net.
    if len(all_rows) < target_n:
        for lang in ("JavaScript", "TypeScript"):
            if len(seen) >= target_n:
                break
            query = f"filename:package-lock.json+language:{lang}"
            page = 1
            while page <= 10 and len(seen) < target_n:
                try:
                    data = _search_page(query, page)
                except Exception:
                    break
                items = data.get("items", [])
                if not items:
                    break
                for item in items:
                    if not _is_root_lockfile(item["path"]):
                        continue
                    repo = item["repository"]
                    fn = repo["full_name"]
                    if fn in seen:
                        continue
                    seen.add(fn)
                    all_rows.append(
                        {
                            "repo_full_name": fn,
                            "default_branch": repo.get("default_branch", "main"),
                            "stars": repo.get("stargazers_count", 0),
                            "lockfile_path": item["path"],
                            "collected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                page += 1

    all_rows = all_rows[:target_n]
    log.info("Collected %d unique repos", len(all_rows))
    return all_rows


def collect_from_curated(curated_path: Path) -> list[dict]:
    """Read owner/repo lines from *curated_path* and build manifest rows.

    Fetches repo metadata (default_branch, stars) from the GitHub Repos API.
    Bypasses the Code Search API entirely — no GITHUB_TOKEN required, though
    providing one raises the rate limit from 60 to 5000 requests/hour.
    """
    lines = [
        ln.strip()
        for ln in curated_path.read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    rows: list[dict] = []
    for full_name in lines:
        url = f"{config.GITHUB_API}/repos/{full_name}"
        try:
            repo_data = get_json(url, headers=github_headers())
        except Exception as exc:
            log.warning("Could not fetch metadata for %s: %s", full_name, exc)
            continue
        rows.append(
            {
                "repo_full_name": full_name,
                "default_branch": repo_data.get("default_branch", "main"),
                "stars": repo_data.get("stargazers_count", 0),
                "lockfile_path": "package-lock.json",
                "collected_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    log.info("Loaded %d repos from curated list %s", len(rows), curated_path)
    return rows


def write_manifest(rows: list[dict]) -> None:
    fields = ["repo_full_name", "default_branch", "stars", "lockfile_path", "collected_at"]
    with open(config.MANIFEST_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %s (%d rows)", config.MANIFEST_CSV, len(rows))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Collect repos with package-lock.json")
    parser.add_argument("--n", type=int, default=config.TARGET_N_REPOS)
    parser.add_argument(
        "--curated",
        metavar="PATH",
        help="Path to a file of owner/repo lines; bypasses GitHub code search.",
    )
    args = parser.parse_args()

    if args.curated:
        rows = collect_from_curated(Path(args.curated))
    else:
        rows = collect_repos(target_n=args.n)
    write_manifest(rows)


if __name__ == "__main__":
    main()

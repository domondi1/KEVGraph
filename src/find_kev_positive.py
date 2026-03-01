"""Bounded, reproducible KEV-positive repository discovery.

Phase 0 — Build a candidate pool (once; reused on --resume):
  • If --seed-file is given, read owner/repo lines directly (no GitHub search).
  • Otherwise run a bounded GitHub Code Search (star-sharded) up to
    --max-candidates repos, filtering to root-level package-lock.json only.
  • Pool is written to data/kev_scan/candidate_pool.csv.

Phase 1 — Scan loop (resumable via --resume):
  For each candidate (in shuffled order, fixed --random-seed):
    1. Download lockfile (cached in data/lockfiles/).
    2. Parse lockfile into a dependency graph (in-memory).
    3. Query OSV for all (package, version) pairs (disk-cached).
    4. Intersect OSV vulns with the live CISA KEV catalogue.
    5. Classify repo as KEV-positive (kev_count > 0) or KEV-zero.
    6. Checkpoint progress to data/kev_scan/progress.json after every repo.
  Stop early once --target-n positive AND --target-control zero repos are found.

Phase 2 — Write final outputs:
  • data/kev_scan/kev_positive_repos.txt
  • data/kev_scan/kev_zero_repos.txt
  • data/kev_scan/kev_density.csv  (per-repo metrics; appended after each repo)

Usage:
    # MRE — 20 positive repos, curated seed, small cap
    python -m src.find_kev_positive \\
        --seed-file data/curated_repos.txt \\
        --max-candidates 500 --target-n 20 --target-control 20 --random-seed 42

    # Paper — 100 positive repos from GitHub search
    python -m src.find_kev_positive \\
        --max-candidates 5000 --target-n 100 --target-control 100 --random-seed 42

    # Resume a previous interrupted run
    python -m src.find_kev_positive --resume --target-n 100
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

from . import config
from .collect_repos import _collect_from_bucket, _is_root_lockfile, collect_from_curated
from .fetch_lockfiles import download_one
from .osv_kev_join import build_vuln_records, fetch_kev_catalogue, query_osv_for_packages
from .parse_lockfile import parse_lockfile
from .rate_limit import get_json, github_headers

log = logging.getLogger(__name__)

# ── Output paths (all under KEV_SCAN_DIR) ────────────────────────────────────
_POOL_CSV       = config.KEV_SCAN_DIR / "candidate_pool.csv"
_PROGRESS_JSON  = config.KEV_SCAN_DIR / "progress.json"
_POSITIVE_TXT   = config.KEV_SCAN_DIR / "kev_positive_repos.txt"
_ZERO_TXT       = config.KEV_SCAN_DIR / "kev_zero_repos.txt"
_DENSITY_CSV    = config.KEV_SCAN_DIR / "kev_density.csv"

_DENSITY_FIELDS = [
    "repo_full_name", "total_pkgs", "total_vulns",
    "kev_count", "kev_rate", "scan_at",
]

_POOL_FIELDS = [
    "repo_full_name", "default_branch", "stars",
    "lockfile_path", "collected_at",
]

_STAR_RANGES = [
    ">=1000",       # high-star first — real projects, more likely to have vulns
    "201..999",
    "51..200",
    "11..50",
    "0..10",
]


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class RepoResult:
    repo_full_name: str
    total_pkgs: int
    total_vulns: int
    kev_count: int
    lockfile_ok: bool
    scan_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def kev_rate(self) -> float:
        return self.kev_count / self.total_vulns if self.total_vulns > 0 else 0.0

    @property
    def is_kev_positive(self) -> bool:
        return self.kev_count > 0


@dataclass
class CheckpointState:
    random_seed: int
    target_n: int
    target_control: int
    processed: list[str] = field(default_factory=list)
    kev_positive_count: int = 0
    kev_zero_count: int = 0
    updated_at: str = ""


# ── Candidate pool ────────────────────────────────────────────────────────────

def _build_pool_from_search(max_candidates: int, star_min: int) -> list[dict]:
    """Run bounded GitHub Code Search and return manifest-schema rows."""
    if not config.GITHUB_TOKEN:
        raise EnvironmentError(
            "GITHUB_TOKEN is required for GitHub Code Search. "
            "Use --seed-file to bypass search, or set GITHUB_TOKEN."
        )
    seen: set[str] = set()
    rows: list[dict] = []
    for star_range in _STAR_RANGES:
        if len(seen) >= max_candidates:
            break
        # Apply star_min filter by adjusting the lower bound of the first range
        bucket_rows = _collect_from_bucket(star_range, seen, max_candidates)
        for r in bucket_rows:
            if r["stars"] >= star_min:
                rows.append(r)
    log.info("Built candidate pool: %d repos", len(rows))
    return rows


def build_candidate_pool(
    max_candidates: int,
    seed_file: Path | None,
    star_min: int,
    resume: bool,
) -> list[dict]:
    """Return candidate pool rows (manifest schema).

    If pool CSV already exists and --resume is set, load it verbatim.
    Otherwise, build it from the seed file or GitHub search, then save it.
    """
    if resume and _POOL_CSV.exists():
        with open(_POOL_CSV) as fh:
            rows = list(csv.DictReader(fh))
        log.info("Loaded existing candidate pool: %d rows", len(rows))
        return rows

    if seed_file is not None:
        rows = collect_from_curated(seed_file)
    else:
        rows = _build_pool_from_search(max_candidates, star_min)

    # Truncate to cap and persist
    rows = rows[:max_candidates]
    _POOL_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(_POOL_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_POOL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    log.info("Saved candidate pool: %d rows → %s", len(rows), _POOL_CSV)
    return rows


# ── Checkpoint ────────────────────────────────────────────────────────────────

def load_checkpoint(target_n: int, target_control: int, random_seed: int) -> CheckpointState:
    if _PROGRESS_JSON.exists():
        data = json.loads(_PROGRESS_JSON.read_text())
        return CheckpointState(**data)
    return CheckpointState(
        random_seed=random_seed,
        target_n=target_n,
        target_control=target_control,
    )


def save_checkpoint(state: CheckpointState) -> None:
    state.updated_at = datetime.now(timezone.utc).isoformat()
    _PROGRESS_JSON.write_text(json.dumps(asdict(state), indent=2))


# ── Per-repo scan ─────────────────────────────────────────────────────────────

def scan_repo(row: dict, kev_catalogue: dict[str, dict]) -> RepoResult:
    """Download lockfile, parse, query OSV+KEV, return RepoResult.

    Lockfiles are cached permanently in data/lockfiles/.
    OSV responses are cached via the disk cache (TTL 72h or SNAPSHOT_MODE).
    """
    repo = row["repo_full_name"]
    branch = row.get("default_branch", "main")
    lockfile_path = row.get("lockfile_path", "package-lock.json")

    # ── 1. Download lockfile ──────────────────────────────────────────────
    dest = download_one(repo, branch, lockfile_path)
    if dest is None:
        log.debug("Skipping %s: lockfile unavailable", repo)
        return RepoResult(
            repo_full_name=repo, total_pkgs=0,
            total_vulns=0, kev_count=0, lockfile_ok=False,
        )

    # ── 2. Parse lockfile ────────────────────────────────────────────────
    try:
        G = parse_lockfile(dest)
    except Exception as exc:
        log.warning("Parse failed for %s: %s", repo, exc)
        return RepoResult(
            repo_full_name=repo, total_pkgs=0,
            total_vulns=0, kev_count=0, lockfile_ok=False,
        )

    if G.number_of_nodes() < config.MIN_DEPS_PER_LOCKFILE:
        log.debug("Skipping %s: only %d nodes", repo, G.number_of_nodes())
        return RepoResult(
            repo_full_name=repo, total_pkgs=G.number_of_nodes(),
            total_vulns=0, kev_count=0, lockfile_ok=False,
        )

    # ── 3. Extract (package, version) pairs ──────────────────────────────
    pkg_versions: list[tuple[str, str]] = []
    for _, attrs in G.nodes(data=True):
        name = attrs.get("name", "")
        ver = attrs.get("version", "")
        if name and ver:
            pkg_versions.append((name, ver))

    total_pkgs = len(pkg_versions)

    # ── 4. Query OSV (cached) ─────────────────────────────────────────────
    # Suppress per-batch progress bar in scan-loop context
    try:
        osv_results = query_osv_for_packages(pkg_versions)
    except Exception as exc:
        log.warning("OSV query failed for %s: %s", repo, exc)
        return RepoResult(
            repo_full_name=repo, total_pkgs=total_pkgs,
            total_vulns=0, kev_count=0, lockfile_ok=True,
        )

    # ── 5. KEV intersection ───────────────────────────────────────────────
    vuln_records = build_vuln_records(osv_results, kev_catalogue)
    total_vulns = len(vuln_records)
    kev_count = sum(1 for r in vuln_records.values() if r.in_kev)

    if kev_count == 0:
        log.warning("repo %s has kev_count=0 (total_vulns=%d)", repo, total_vulns)

    return RepoResult(
        repo_full_name=repo,
        total_pkgs=total_pkgs,
        total_vulns=total_vulns,
        kev_count=kev_count,
        lockfile_ok=True,
    )


# ── Output helpers ────────────────────────────────────────────────────────────

def _append_density_row(result: RepoResult) -> None:
    """Append one row to kev_density.csv; write header on first call."""
    write_header = not _DENSITY_CSV.exists()
    """ with open(_DENSITY_CSV, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_DENSITY_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow({
            "repo_full_name": result.repo_full_name,
            "total_pkgs": result.total_pkgs,
            "total_vulns": result.total_vulns,
            "kev_count": result.kev_count,
            "kev_rate": f"{result.kev_rate:.6f}",
            "scan_at": result.scan_at,
        })
    fh.flush() """  # ensure crash-safe append


def write_final_outputs(
    kev_positive: list[str],
    kev_zero: list[str],
) -> None:
    _POSITIVE_TXT.write_text("\n".join(kev_positive) + "\n" if kev_positive else "")
    _ZERO_TXT.write_text("\n".join(kev_zero) + "\n" if kev_zero else "")
    log.info(
        "Wrote %s (%d repos) and %s (%d repos)",
        _POSITIVE_TXT, len(kev_positive),
        _ZERO_TXT, len(kev_zero),
    )


# ── Main orchestration ────────────────────────────────────────────────────────

def run(
    seed_file: Path | None,
    max_candidates: int,
    target_n: int,
    target_control: int,
    random_seed: int,
    resume: bool,
    star_min: int,
) -> None:
    # ── Phase 0: Candidate pool ───────────────────────────────────────────
    pool = build_candidate_pool(max_candidates, seed_file, star_min, resume)
    if not pool:
        log.error("Candidate pool is empty — nothing to scan.")
        sys.exit(1)

    # Deterministic shuffle (same seed → same order every run)
    rng = random.Random(random_seed)
    indices = list(range(len(pool)))
    rng.shuffle(indices)
    ordered = [pool[i] for i in indices]

    # ── Resume: skip already-processed repos ─────────────────────────────
    checkpoint = load_checkpoint(target_n, target_control, random_seed)
    if resume and checkpoint.processed:
        seen_set = set(checkpoint.processed)
        ordered = [r for r in ordered if r["repo_full_name"] not in seen_set]
        log.info(
            "Resuming: %d already processed (positive=%d, zero=%d); %d remain",
            len(checkpoint.processed),
            checkpoint.kev_positive_count,
            checkpoint.kev_zero_count,
            len(ordered),
        )

    kev_positive: list[str] = list(checkpoint.processed) if resume else []
    # Rebuild positive/zero lists from density CSV if resuming
    # (simpler to rebuild than to serialise two lists in checkpoint)
    kev_positive_set: set[str] = set()
    kev_zero_set: set[str] = set()
    if resume and _DENSITY_CSV.exists():
        with open(_DENSITY_CSV) as fh:
            for row in csv.DictReader(fh):
                if int(row.get("kev_count", 0)) > 0:
                    kev_positive_set.add(row["repo_full_name"])
                else:
                    kev_zero_set.add(row["repo_full_name"])

    # ── Phase 1: Scan loop ────────────────────────────────────────────────
    log.info("Loading CISA KEV catalogue…")
    kev_catalogue = fetch_kev_catalogue()
    log.info("KEV catalogue: %d entries", len(kev_catalogue))

    log.info(
        "Scanning up to %d candidates | target positive=%d control=%d | seed=%d",
        len(ordered), target_n, target_control, random_seed,
    )

    pbar = tqdm(ordered, desc="Scanning repos", unit="repo")
    for row in pbar:
        repo = row["repo_full_name"]

        # Early-exit check
        pos_done = len(kev_positive_set) >= target_n
        ctl_done = len(kev_zero_set) >= target_control
        if pos_done and ctl_done:
            log.info("Targets reached — stopping early.")
            break

        result = scan_repo(row, kev_catalogue)
        _append_density_row(result)

        if result.lockfile_ok:
            if result.is_kev_positive:
                if len(kev_positive_set) < target_n:
                    kev_positive_set.add(repo)
            else:
                if len(kev_zero_set) < target_control:
                    kev_zero_set.add(repo)

        # Update checkpoint after every repo
        checkpoint.processed.append(repo)
        checkpoint.kev_positive_count = len(kev_positive_set)
        checkpoint.kev_zero_count = len(kev_zero_set)
        save_checkpoint(checkpoint)

        pbar.set_postfix(
            positive=len(kev_positive_set),
            zero=len(kev_zero_set),
        )

    # ── Phase 2: Final outputs ────────────────────────────────────────────
    write_final_outputs(sorted(kev_positive_set), sorted(kev_zero_set))

    log.info(
        "Done. KEV-positive: %d / %d  |  KEV-zero (control): %d / %d",
        len(kev_positive_set), target_n,
        len(kev_zero_set), target_control,
    )
    if len(kev_positive_set) < target_n:
        log.warning(
            "Only %d KEV-positive repos found (target %d). "
            "Increase --max-candidates or use a wider search.",
            len(kev_positive_set), target_n,
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Bounded KEV-positive repository discovery.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--seed-file", metavar="PATH",
        help="Path to owner/repo file; skips GitHub search entirely.",
    )
    parser.add_argument(
        "--max-candidates", type=int, default=config.DEFAULT_MAX_CANDIDATES,
        help="Maximum candidate repos to fetch from GitHub search.",
    )
    parser.add_argument(
        "--target-n", type=int, default=100,
        help="Stop after this many KEV-positive repos are found.",
    )
    parser.add_argument(
        "--target-control", type=int, default=100,
        help="Collect this many KEV-zero repos as the control set.",
    )
    parser.add_argument(
        "--random-seed", type=int, default=config.DEFAULT_RANDOM_SEED,
        help="Seed for pool shuffle (ensures deterministic ordering).",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Reload candidate_pool.csv and progress.json; skip processed repos.",
    )
    parser.add_argument(
        "--star-min", type=int, default=0,
        help="Exclude repos below this star count from the candidate pool.",
    )
    args = parser.parse_args()

    run(
        seed_file=Path(args.seed_file) if args.seed_file else None,
        max_candidates=args.max_candidates,
        target_n=args.target_n,
        target_control=args.target_control,
        random_seed=args.random_seed,
        resume=args.resume,
        star_min=args.star_min,
    )


if __name__ == "__main__":
    main()

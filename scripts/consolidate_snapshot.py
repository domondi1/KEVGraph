#!/usr/bin/env python3
"""Create a reproducibility snapshot from the current pipeline cache.

Extracts the frozen CISA KEV catalogue from the disk cache, writes it to a
dated snapshot directory alongside a PROVENANCE.json and SHA256SUMS file.

Usage:
    python scripts/consolidate_snapshot.py
    python scripts/consolidate_snapshot.py --tag 2024-03-15

Produces:
    data/snapshots/<tag>/
        kev_catalogue.json   — frozen CISA KEV feed as returned by the API
        PROVENANCE.json      — fetch timestamp, entry count, pipeline version
        SHA256SUMS           — SHA-256 checksums of all snapshot files

To use the snapshot in a later run:
    export KEVGRAPH_KEV_SNAPSHOT=data/snapshots/<tag>/kev_catalogue.json
    export KEVGRAPH_SNAPSHOT_MODE=1   # freeze all other cached API responses
    python -m src.pipeline --stage join
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import cache, config  # noqa: E402  (after sys.path manipulation)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _find_kev_in_cache() -> dict | None:
    """Look up the CISA KEV entry in the disk cache and return its payload."""
    payload = cache.get("GET", config.CISA_KEV_URL)
    if payload is None:
        return None
    return payload


def consolidate(tag: str) -> Path:
    snapshot_dir = config.SNAPSHOT_DIR / tag
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    # ── Extract KEV catalogue ─────────────────────────────────────────────────
    kev_payload = _find_kev_in_cache()
    if kev_payload is None:
        sys.exit(
            "KEV catalogue not found in cache.\n"
            "Run 'python -m src.pipeline --stage join' first to populate the cache,\n"
            "then re-run this script."
        )

    kev_path = snapshot_dir / "kev_catalogue.json"
    kev_path.write_text(json.dumps(kev_payload, indent=2))

    entry_count = len(kev_payload.get("vulnerabilities", []))
    print(f"KEV entries written: {entry_count}")

    # ── PROVENANCE.json ───────────────────────────────────────────────────────
    # Read __version__ without importing the full package
    version_file = config.ROOT_DIR / "src" / "__init__.py"
    pipeline_version = "unknown"
    if version_file.exists():
        for line in version_file.read_text().splitlines():
            if line.startswith("__version__"):
                pipeline_version = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    provenance = {
        "schema_version": "1.0",
        "snapshot_tag": tag,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "pipeline_version": pipeline_version,
        "data_sources": {
            "cisa_kev": {
                "url": config.CISA_KEV_URL,
                "entry_count": entry_count,
                "snapshot_file": "kev_catalogue.json",
            },
            "osv": {
                "note": (
                    "OSV responses are preserved in data/cached_api/. "
                    "Set KEVGRAPH_SNAPSHOT_MODE=1 to prevent TTL expiry during replay."
                ),
                "cache_dir": "data/cached_api/",
            },
        },
        "reproduction": {
            "kev": "export KEVGRAPH_KEV_SNAPSHOT=data/snapshots/{tag}/kev_catalogue.json".format(
                tag=tag
            ),
            "osv_and_other": "export KEVGRAPH_SNAPSHOT_MODE=1",
        },
    }
    prov_path = snapshot_dir / "PROVENANCE.json"
    prov_path.write_text(json.dumps(provenance, indent=2))

    # ── SHA256SUMS ────────────────────────────────────────────────────────────
    files_to_checksum = [kev_path, prov_path]
    sums_lines = [
        f"{_sha256_file(p)}  {p.name}" for p in files_to_checksum
    ]
    sums_path = snapshot_dir / "SHA256SUMS"
    sums_path.write_text("\n".join(sums_lines) + "\n")

    print(f"Snapshot written to: {snapshot_dir}")
    print(f"  {kev_path.name}   ({kev_path.stat().st_size:,} bytes)")
    print(f"  {prov_path.name}")
    print(f"  {sums_path.name}")
    print()
    print("To reproduce with this snapshot:")
    print(f"  export KEVGRAPH_KEV_SNAPSHOT={kev_path}")
    print( "  export KEVGRAPH_SNAPSHOT_MODE=1")
    print( "  python -m src.pipeline --stage join")

    return snapshot_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Consolidate pipeline cache into a snapshot.")
    parser.add_argument(
        "--tag",
        default=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"),
        help="Snapshot tag / subdirectory name (default: today's UTC date)",
    )
    args = parser.parse_args()
    consolidate(args.tag)


if __name__ == "__main__":
    main()

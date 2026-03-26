"""Stage 3: Parse each package-lock.json into a NetworkX dependency graph.

Supports lockfile versions 1, 2, and 3 (npm v5–v9).

Each graph is serialised as GraphML to  data/graphs/<owner>__<repo>.graphml
with node attributes:
    name        – npm package name
    version     – resolved semver string
    dev         – "true" / "false" (whether it's a devDependency)

Edge semantics: (A) --requires--> (B) means A declares B as a dependency.

Usage:
    python -m src.parse_lockfile
"""

from __future__ import annotations

import logging
from pathlib import Path

import networkx as nx
from tqdm import tqdm

from . import config
from .ecosystems.base import EcosystemAdapter

log = logging.getLogger(__name__)


def parse_lockfile(path: Path) -> nx.DiGraph:
    """Parse a single package-lock.json file, return directed dep graph.

    Backward-compatible entry point: delegates to NpmAdapter.parse_lockfile().
    """
    from .ecosystems.npm import NpmAdapter
    return NpmAdapter().parse_lockfile(path)


def parse_all(adapter: EcosystemAdapter | None = None) -> int:
    """Parse every lockfile in LOCKFILE_DIR, write GraphML. Returns count."""
    if adapter is None:
        from .ecosystems.npm import NpmAdapter
        adapter = NpmAdapter()

    lockfiles = sorted(config.LOCKFILE_DIR.glob("*.json"))
    if not lockfiles:
        raise FileNotFoundError("No lockfiles found – run fetch_lockfiles first.")

    parsed = 0
    for lf in tqdm(lockfiles, desc="Parsing lockfiles", unit="file"):
        dest = config.GRAPH_DIR / f"{lf.stem}.graphml"
        if dest.exists():
            parsed += 1
            continue
        try:
            G = adapter.parse_lockfile(lf)
            if G.number_of_nodes() < config.MIN_DEPS_PER_LOCKFILE:
                log.debug("Skipping %s (only %d deps)", lf.stem, G.number_of_nodes())
                continue
            nx.write_graphml(G, str(dest))
            parsed += 1
        except Exception as exc:
            log.warning("Failed to parse %s: %s", lf.name, exc)

    log.info("Parsed %d lockfiles -> GraphML", parsed)
    return parsed


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parse_all()


if __name__ == "__main__":
    main()

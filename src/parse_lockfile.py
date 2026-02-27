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

import json
import logging
from pathlib import Path

import networkx as nx
from tqdm import tqdm

from . import config

log = logging.getLogger(__name__)


def _node_id(name: str, version: str) -> str:
    return f"{name}@{version}"


# ── lockfileVersion 1 ────────────────────────────────────────────────────────

def _parse_v1(data: dict) -> nx.DiGraph:
    """Parse npm lockfile version 1 (flat 'dependencies' dict)."""
    G = nx.DiGraph()
    deps = data.get("dependencies", {})

    for pkg_name, info in deps.items():
        ver = info.get("version", "0.0.0")
        nid = _node_id(pkg_name, ver)
        G.add_node(nid, name=pkg_name, version=ver, dev=str(info.get("dev", False)).lower())
        for req_name in info.get("requires", {}):
            req_info = deps.get(req_name, {})
            req_ver = req_info.get("version", "0.0.0")
            G.add_edge(nid, _node_id(req_name, req_ver))

    return G


# ── lockfileVersion 2 / 3 ────────────────────────────────────────────────────

def _parse_v2(data: dict) -> nx.DiGraph:
    """Parse npm lockfile version 2 or 3 ('packages' map with node_modules paths)."""
    G = nx.DiGraph()
    packages = data.get("packages", {})

    # Build lookup: path -> (name, version)
    path_to_nid: dict[str, str] = {}
    for path, info in packages.items():
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        if not name:
            continue
        ver = info.get("version", "0.0.0")
        nid = _node_id(name, ver)
        path_to_nid[path] = nid
        G.add_node(nid, name=name, version=ver, dev=str(info.get("dev", False)).lower())

    for path, info in packages.items():
        src_nid = path_to_nid.get(path)
        if not src_nid:
            continue
        all_deps: dict[str, str] = {}
        all_deps.update(info.get("dependencies", {}))
        all_deps.update(info.get("devDependencies", {}))
        all_deps.update(info.get("optionalDependencies", {}))

        for dep_name in all_deps:
            # Resolve: walk up the node_modules tree
            candidate_paths = []
            parts = path.split("node_modules/")
            for i in range(len(parts), 0, -1):
                prefix = "node_modules/".join(parts[:i])
                if prefix:
                    prefix += "/"
                candidate_paths.append(f"{prefix}node_modules/{dep_name}")

            for cp in candidate_paths:
                if cp in path_to_nid:
                    G.add_edge(src_nid, path_to_nid[cp])
                    break

    return G


def parse_lockfile(path: Path) -> nx.DiGraph:
    """Parse a single package-lock.json file, return directed dep graph."""
    with open(path) as fh:
        data = json.load(fh)

    lf_version = data.get("lockfileVersion", 1)
    if lf_version >= 2:
        G = _parse_v2(data)
    else:
        G = _parse_v1(data)

    # Attach repo-level metadata
    G.graph["lockfileVersion"] = lf_version
    G.graph["source"] = path.stem
    return G


def parse_all() -> int:
    """Parse every lockfile in LOCKFILE_DIR, write GraphML. Returns count."""
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
            G = parse_lockfile(lf)
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

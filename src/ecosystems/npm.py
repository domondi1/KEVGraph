"""npm ecosystem adapter for KEVGraph.

Logic moved from:
  - src/parse_lockfile.py  (_node_id, _parse_v1, _parse_v2, parse_lockfile)
  - src/collect_repos.py   (_is_root_lockfile, query construction)
  - src/candidate_fixes.py (_latest_from_npm, _fixed_from_deps_dev, _pick_best_fix)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import networkx as nx

from .. import config
from ..rate_limit import get_json
from .base import EcosystemAdapter

log = logging.getLogger(__name__)


# ── Graph helpers (moved from parse_lockfile.py) ──────────────────────────────

def _node_id(name: str, version: str) -> str:
    return f"{name}@{version}"


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


def _parse_v2(data: dict) -> nx.DiGraph:
    """Parse npm lockfile version 2 or 3 ('packages' map with node_modules paths)."""
    G = nx.DiGraph()
    packages = data.get("packages", {})

    # Build lookup: path -> node id
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


# ── NpmAdapter ────────────────────────────────────────────────────────────────

class NpmAdapter(EcosystemAdapter):
    """npm ecosystem adapter."""

    # ── EcosystemAdapter interface ─────────────────────────────────────────

    @property
    def lockfile_filename(self) -> str:
        return "package-lock.json"

    @property
    def lockfile_ext(self) -> str:
        return ".json"

    @property
    def osv_ecosystem(self) -> str:
        return "npm"

    def parse_lockfile(self, path: Path) -> nx.DiGraph:
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

    def github_search_query(self, star_range: str) -> str:
        return f"filename:package-lock.json+in:path+stars:{star_range}"

    def supplementary_github_query(self, language: str) -> str:
        return f"filename:package-lock.json+language:{language}"

    def is_root_lockfile(self, path: str) -> bool:
        return path == "package-lock.json" or path.endswith("/package-lock.json")

    @property
    def supplementary_language_filters(self) -> list[str]:
        return ["JavaScript", "TypeScript"]

    def normalize_package_name(self, name: str) -> str:
        return name

    def resolve_fixed_version(
        self,
        pkg_name: str,
        osv_fixed: str | None,
        vuln_aliases: list[str],
    ) -> str | None:
        """Cascade: OSV fixed_version → deps.dev → npm registry latest."""
        if osv_fixed:
            return osv_fixed
        fix = self._fixed_from_deps_dev(pkg_name, vuln_aliases)
        if fix:
            return fix
        return self._latest_from_npm(pkg_name)

    # ── Private helpers ────────────────────────────────────────────────────

    def _latest_from_npm(self, pkg_name: str) -> str | None:
        """Fetch the 'latest' dist-tag from the npm registry."""
        url = f"{config.NPM_REGISTRY}/{pkg_name}"
        try:
            data = get_json(url)
            return data.get("dist-tags", {}).get("latest")
        except Exception:
            return None

    def _fixed_from_deps_dev(self, pkg_name: str, vuln_aliases: list[str]) -> str | None:
        """Query deps.dev advisory endpoint for a fix version."""
        url = f"{config.DEPS_DEV_API}/systems/npm/packages/{pkg_name}"
        try:
            data = get_json(url)
            versions = data.get("versions", [])
            if versions:
                return versions[-1].get("versionKey", {}).get("version")
        except Exception:
            return None
        return None

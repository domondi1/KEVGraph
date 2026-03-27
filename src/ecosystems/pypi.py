"""PyPI ecosystem adapter for KEVGraph.

Parses poetry.lock (TOML format) into a NetworkX dependency graph and
provides PyPI-specific implementations of the EcosystemAdapter interface.

poetry.lock parsing notes:
- Uses Python stdlib tomllib (Python 3.11+) with tomli as fallback.
- Dev-group detection requires Poetry 1.2+ which adds a `groups` field to
  each [[package]] block.  Older poetry.lock files omit `groups`, so those
  packages default to dev="false" (conservative — treats everything as prod).
- Dependency edges are derived from [package.dependencies] in each block.
  Version specifiers are recorded but ignored for graph structure (we only
  care about the dependency relationship, not the pinned version range).

Fixed-version resolution:
1. Use OSV fixed_version if present (most reliable).
2. Fall back to PyPI JSON API (/pypi/{name}/json) for the latest stable
   version. This is a best-effort heuristic — "latest" may not be the
   minimum safe version.  It is documented as a fallback, never claimed
   to be the exact fix boundary.
3. Return None if neither source is available.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import networkx as nx

from .. import config
from ..rate_limit import get_json
from .base import EcosystemAdapter

log = logging.getLogger(__name__)

PYPI_JSON_API = "https://pypi.org/pypi"

# Size-based sharding for poetry.lock discovery.
# GitHub code search does not support stars: for code queries, so we shard by
# file size (bytes) instead.  The keys mirror collect_repos._STAR_RANGES so
# that each bucket call produces a different query and unique results.
#
# Ordering rationale: we prioritize mid-range sizes (8KB-200KB) first because
# those correspond to projects with 20-500 dependencies — above the
# MIN_DEPS_PER_LOCKFILE threshold.  Tiny files (< 8KB) come last; they tend
# to have < 10 packages and get filtered out anyway.
_STAR_TO_SIZE: dict[str, str] = {
    "0..10":       "25001..80000",    # 50-200 deps — most productive range
    "11..50":      "8001..25000",     # 20-50 deps
    "51..200":     "80001..200000",   # 200-500 deps — large projects
    "201..1000":   "200001..600000",  # very large projects
    "1001..5000":  "2001..8000",      # small projects (5-20 deps)
    "5001..50000": "100..2000",       # tiny / near-empty (usually filtered)
    ">=50001":     "600001..2000000", # giant monorepos
}


def _load_toml(path: Path) -> dict:
    """Load a TOML file using tomllib (stdlib, Python 3.11+) or tomli."""
    try:
        import tomllib  # type: ignore[import]
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import,no-redef]
        except ImportError as exc:
            raise ImportError(
                "Parsing poetry.lock requires 'tomllib' (Python 3.11+) or 'tomli'. "
                "Install tomli:  pip install tomli"
            ) from exc

    with open(path, "rb") as fh:
        return tomllib.load(fh)


# ── PyPIAdapter ───────────────────────────────────────────────────────────────


class PyPIAdapter(EcosystemAdapter):
    """PyPI ecosystem adapter — lockfile: poetry.lock."""

    # ── EcosystemAdapter interface ─────────────────────────────────────────

    @property
    def lockfile_filename(self) -> str:
        return "poetry.lock"

    @property
    def lockfile_ext(self) -> str:
        return ".toml"

    @property
    def osv_ecosystem(self) -> str:
        return "PyPI"

    def github_search_query(self, star_range: str) -> str:
        """Return a size-sharded code search query.

        GitHub code search does not support the stars: qualifier, so we shard
        by file size (bytes) instead.  Each star_range bucket maps to a
        distinct size range, ensuring different pages of results per bucket.
        """
        size_range = _STAR_TO_SIZE.get(star_range, "100..2000000")
        return f"filename:poetry.lock+size:{size_range}"

    def supplementary_github_query(self, language: str) -> str:
        # Language filter is not useful for TOML files; fall back to a broad
        # content query.  The supplementary pass only fires when the primary
        # star-bucket pass falls short of the target.
        return f"filename:poetry.lock"

    def is_root_lockfile(self, path: str) -> bool:
        """Accept poetry.lock at the root or one level deep.

        Reject lockfiles nested inside virtualenvs or sub-packages
        more than two directory levels deep.
        """
        if path == "poetry.lock":
            return True
        if path.endswith("/poetry.lock"):
            # Allow at most one subdirectory level
            depth = path.count("/")
            return depth == 1
        return False

    @property
    def supplementary_language_filters(self) -> list[str]:
        return ["Python"]

    def normalize_package_name(self, name: str) -> str:
        """Normalize per PEP 503: lowercase, collapse [-_.] runs to '-'."""
        return re.sub(r"[-_.]+", "-", name).lower()

    def parse_lockfile(self, path: Path) -> nx.DiGraph:
        """Parse poetry.lock into a NetworkX DiGraph.

        Node attributes (per EcosystemAdapter contract):
            name    – normalized PyPI package name
            version – exact version string from the lock file
            dev     – "true" / "false"

        Dev detection:
            Poetry 1.2+ adds  groups = ["dev"]  (or ["main"], etc.) to each
            [[package]] block.  When present, a package is marked dev="true"
            only if ALL its groups are non-main (i.e., the package never
            appears in the default/main group).

            Older poetry.lock files omit the `groups` field entirely.  In
            that case we default to dev="false" (conservative: treat as prod).

        Edge semantics: A → B means package A lists B in its
        [package.dependencies] block.  Version specifier strings are ignored;
        only the package name is used to construct the edge.
        """
        data = _load_toml(path)
        packages: list[dict] = data.get("package", [])

        G = nx.DiGraph()

        # Pass 1: add nodes, build name → node-id lookup
        name_to_nid: dict[str, str] = {}
        for pkg in packages:
            raw_name = pkg.get("name", "")
            version = pkg.get("version", "")
            if not raw_name or not version:
                continue

            norm_name = self.normalize_package_name(raw_name)
            nid = f"{norm_name}@{version}"

            # Dev-group detection
            groups = pkg.get("groups", None)
            if groups is not None and isinstance(groups, list):
                # dev if all groups are non-"main"
                dev = "true" if groups and all(g != "main" for g in groups) else "false"
            else:
                # groups field absent (older Poetry) — conservative: treat as prod
                dev = "false"

            G.add_node(nid, name=norm_name, version=version, dev=dev)
            # Map both normalized and original name to handle mixed cases
            name_to_nid[norm_name] = nid
            name_to_nid[self.normalize_package_name(raw_name)] = nid

        # Pass 2: add dependency edges
        for pkg in packages:
            raw_name = pkg.get("name", "")
            if not raw_name:
                continue
            norm_name = self.normalize_package_name(raw_name)
            src_nid = name_to_nid.get(norm_name)
            if not src_nid:
                continue

            deps = pkg.get("dependencies", {})
            if not isinstance(deps, dict):
                continue

            for dep_raw in deps:
                # Skip Python version constraint pseudo-entry
                if dep_raw.lower() == "python":
                    continue
                dep_norm = self.normalize_package_name(dep_raw)
                dep_nid = name_to_nid.get(dep_norm)
                if dep_nid and dep_nid != src_nid:
                    G.add_edge(src_nid, dep_nid)

        G.graph["source"] = path.stem
        G.graph["ecosystem"] = "PyPI"
        return G

    def resolve_fixed_version(
        self,
        pkg_name: str,
        osv_fixed: str | None,
        vuln_aliases: list[str],
    ) -> str | None:
        """Cascade: OSV fixed_version → PyPI latest stable.

        Step 1: OSV fixed_version (authoritative fix boundary from the
                advisory database).
        Step 2: PyPI JSON API /pypi/{name}/json → info.version (latest
                published stable release).  This is a best-effort fallback
                when OSV lacks a fix version.  It is NOT guaranteed to be
                the minimum safe version — it is the current latest, which
                is usually safe but may overshoot.
        Step 3: Return None if neither source yields a version.
        """
        if osv_fixed:
            return osv_fixed
        return self._latest_from_pypi(pkg_name)

    # ── Private helpers ────────────────────────────────────────────────────

    def _latest_from_pypi(self, pkg_name: str) -> str | None:
        """Fetch the latest stable version from the PyPI JSON API."""
        norm = self.normalize_package_name(pkg_name)
        url = f"{PYPI_JSON_API}/{norm}/json"
        try:
            data = get_json(url)
            version = data.get("info", {}).get("version")
            return version or None
        except Exception as exc:
            log.debug("PyPI API failed for %s: %s", pkg_name, exc)
            return None

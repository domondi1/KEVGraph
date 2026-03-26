"""Abstract base class for ecosystem adapters.

An EcosystemAdapter encapsulates all logic that is specific to a particular
package ecosystem (npm, PyPI, Maven, …) so that the KEVGraph core pipeline
remains ecosystem-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import networkx as nx


class EcosystemAdapter(ABC):
    """Ecosystem-agnostic interface for lockfile parsing and package operations."""

    @property
    @abstractmethod
    def osv_ecosystem(self) -> str:
        """OSV ecosystem identifier (e.g., 'npm', 'PyPI').

        Used as the ``ecosystem`` field in OSV querybatch payloads and for
        matching against the ``ecosystem`` attribute in OSV affected-package
        records.
        """
        ...

    @abstractmethod
    def parse_lockfile(self, path: Path) -> nx.DiGraph:
        """Parse the ecosystem lockfile at *path* into a dependency graph.

        Returns a NetworkX DiGraph whose nodes carry at minimum the attributes:
            name     – package name
            version  – installed version string
            dev      – "true" / "false" (whether it is a dev dependency)
        """
        ...

    @abstractmethod
    def github_search_query(self, star_range: str) -> str:
        """Return a GitHub code search query string for the given star range.

        Used for the primary star-bucketed discovery pass in Stage 1.

        Example (npm):
            "filename:package-lock.json+in:path+stars:11..50"
        """
        ...

    @abstractmethod
    def supplementary_github_query(self, language: str) -> str:
        """Return a GitHub code search query string for a language filter.

        Used for the supplementary discovery pass when the primary star-bucket
        pass has not yet reached the target repo count.

        Example (npm):
            "filename:package-lock.json+language:JavaScript"
        """
        ...

    @abstractmethod
    def is_root_lockfile(self, path: str) -> bool:
        """Return True if *path* refers to a root-level lockfile.

        Rejects lockfiles nested inside sub-packages or sub-directories so
        that the manifest only contains top-level dependency manifests.

        Example (npm): True for "package-lock.json" and "pkg/package-lock.json",
        but False for "node_modules/foo/package-lock.json".
        """
        ...

    @property
    @abstractmethod
    def supplementary_language_filters(self) -> list[str]:
        """Language names for supplementary GitHub code search queries.

        Each language triggers one supplementary search pass when the primary
        star-bucket pass falls short of the target.

        Example (npm): ["JavaScript", "TypeScript"]
        """
        ...

    @abstractmethod
    def normalize_package_name(self, name: str) -> str:
        """Normalize a package name for use in API queries.

        For most ecosystems this is a no-op. PyPI normalises to lowercase with
        hyphens; npm names are already canonical.
        """
        ...

    @abstractmethod
    def resolve_fixed_version(
        self,
        pkg_name: str,
        osv_fixed: str | None,
        vuln_aliases: list[str],
    ) -> str | None:
        """Resolve the best available fix version for a vulnerable package.

        Cascade strategy (ecosystem-specific):
          1. Use the OSV ``fixed_version`` if present.
          2. Fall back to the ecosystem's advisory/registry API.
          3. Return None if no fix version can be determined.
        """
        ...

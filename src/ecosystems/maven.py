"""Maven ecosystem adapter for KEVGraph.

Parses pom.xml (Maven's Project Object Model) into a NetworkX dependency graph
and provides Maven-specific implementations of the EcosystemAdapter interface.

Lockfile strategy — DESIGN DECISION
=====================================
Maven has no universal lockfile equivalent to npm's package-lock.json.  Three
options were evaluated:

  A. Maven Dependency Lock Plugin (pom.lock / maven-dependency-lock.json)
     — Real lockfile semantics, but adoption is extremely low (< 0.1% of repos).
     — Searching GitHub for pom.lock returns near-zero results.  Unusable.

  B. mvn dependency:tree output
     — Full transitive resolution, but requires running the Maven build.
     — Cannot be discovered via GitHub code search.  Not reproducible from
       static files.  Disqualified.

  C. pom.xml direct-dependency extraction  ← CHOSEN
     — Present in every Maven project (universal, ~100% adoption).
     — Declares direct dependencies; most mature projects pin exact versions.
     — Dependencies with property placeholders (${…}) or version ranges are
       silently skipped — only exact, pinned versions are recorded.
     — KEV signal is extremely high: log4j (CVE-2021-44228 / CISA KEV),
       Spring Framework, Apache Struts, and dozens of other well-known Java
       CVEs are matched via OSV's "Maven" ecosystem identifier.
     — This is the same approach used by Dependabot, OSV-Scanner, and OWASP
       Dependency-Check for Maven projects.

Rationale for choosing C:
  The goal is KEV signal density.  Java/Maven has by far the most KEV-positive
  packages (log4j alone accounts for a large fraction of CISA KEV entries).
  Near-zero repos would be discoverable with option A; option B is non-static.
  Option C trades lockfile precision for coverage — an acceptable tradeoff for
  a research evaluation comparing ecosystems.

pom.xml parsing notes:
- Only <dependencies> block is parsed, NOT <dependencyManagement> (BOM imports).
- groupId:artifactId is the canonical Maven package identity used by OSV.
- Scope mapping: test/provided → dev="true"; compile/runtime/import → dev="false".
- A virtual root node (project groupId:artifactId) is added; all direct deps
  are connected to it to produce a well-formed graph.
- Both namespace-qualified and bare XML elements are handled.

Fixed-version resolution:
1. OSV fixed_version if present (authoritative advisory fix boundary).
2. Maven Central Search API (/solrsearch/select) for the latest release.
   Best-effort; latest is usually safe but may overshoot the minimum fix.
3. Return None if neither yields a version.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import networkx as nx

from ..rate_limit import get_json
from .base import EcosystemAdapter

log = logging.getLogger(__name__)

# Maven Central Search API — no auth, 5 req/s is safe
MAVEN_CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"

# Maven POM XML namespace (Maven 4 enforces it; many Maven 3 pom.xml files omit it)
_POM_NS = "http://maven.apache.org/POM/4.0.0"
_NS = {"m": _POM_NS}

# Reject versions that cannot be resolved statically
_PROP_RE = re.compile(r"\$\{")         # ${spring.version}
_RANGE_RE = re.compile(r"[\[\](,]")   # [1.0,2.0), (,1.9], LATEST, RELEASE

# Scope values that indicate a dev/test-only dependency
_DEV_SCOPES = {"test", "provided"}

# Content-based query buckets for GitHub code search.
# GitHub code search does NOT support the stars: qualifier; only repository
# search does.  We repurpose the star_range key to select different content
# terms so each "bucket" discovers a distinct slice of the Maven ecosystem.
# Each query targets pom.xml files that contain a KEV-relevant dependency or
# a high-signal Maven keyword, maximising KEV density in the collected corpus.
_CONTENT_BUCKETS: dict[str, str] = {
    "0..10":       "log4j",                 # log4shell repos
    "11..50":      "springframework",        # Spring Framework / Spring4Shell
    "51..200":     "jackson-databind",       # Jackson RCE CVEs
    "201..1000":   "commons-collections",    # Apache Commons deserialization
    "1001..5000":  "struts",                 # Apache Struts CVEs (incl. Equifax)
    "5001..50000": "hibernate",              # Hibernate ORM
    ">=50001":     "spring-boot",            # General Spring Boot repos
}

# Directories that indicate a pom.xml is NOT a root-level project manifest
_REJECT_DIRS = frozenset({
    "target", ".m2", "build", "vendor", ".gradle",
    "generated-sources", "generated-test-sources",
    "node_modules", "dist", "out",
})


# ── XML helpers ───────────────────────────────────────────────────────────────


def _text(elem: ET.Element, tag: str) -> str:
    """Return stripped text of a direct child element, or '' if absent.

    Tries the Maven namespace first, then bare tag name, to handle both
    namespace-qualified and unqualified pom.xml files.
    """
    child = elem.find(f"m:{tag}", _NS)
    if child is None:
        child = elem.find(tag)
    return (child.text or "").strip() if child is not None else ""


def _is_exact_version(version: str) -> bool:
    """Return True iff version is a plain, pinned release string."""
    if not version:
        return False
    if _PROP_RE.search(version):
        return False
    if _RANGE_RE.search(version):
        return False
    # Reject Maven magic tokens
    if version.upper() in ("LATEST", "RELEASE"):
        return False
    return True


# ── POM parser ────────────────────────────────────────────────────────────────


def _parse_pom(path: Path) -> nx.DiGraph:
    """Parse a pom.xml into a directed dependency graph.

    Node attributes (EcosystemAdapter contract):
        name    – "groupId:artifactId"
        version – pinned version string
        dev     – "true" if scope is test/provided, else "false"

    Graph structure:
        A virtual root node (the project itself) has directed edges to each
        declared direct dependency with a resolvable version.  This produces
        a well-formed connected graph for downstream planners.
    """
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        log.debug("XML parse error in %s: %s", path, exc)
        return nx.DiGraph()

    root_elem = tree.getroot()
    G = nx.DiGraph()

    # ── Project root node ─────────────────────────────────────────────────
    proj_group = _text(root_elem, "groupId") or "unknown"
    proj_artifact = _text(root_elem, "artifactId") or path.stem
    proj_version = _text(root_elem, "version") or "0.0.0"
    # Normalize version: skip property placeholders for the root version
    if not _is_exact_version(proj_version):
        proj_version = "0.0.0"

    root_name = f"{proj_group}:{proj_artifact}"
    root_nid = f"{root_name}@{proj_version}"
    G.add_node(root_nid, name=root_name, version=proj_version, dev="false")

    # ── Direct dependencies ───────────────────────────────────────────────
    # Search for <dependencies> as a direct child (NOT under <dependencyManagement>)
    deps_block = root_elem.find(f"m:dependencies", _NS)
    if deps_block is None:
        deps_block = root_elem.find("dependencies")

    if deps_block is None:
        G.graph["source"] = path.stem
        G.graph["ecosystem"] = "Maven"
        return G

    for dep in list(deps_block):
        group_id = _text(dep, "groupId")
        artifact_id = _text(dep, "artifactId")
        version = _text(dep, "version")
        scope = _text(dep, "scope").lower() or "compile"

        if not group_id or not artifact_id:
            continue
        if not _is_exact_version(version):
            # Skip unresolvable (property placeholder / range / empty)
            continue

        pkg_name = f"{group_id}:{artifact_id}"
        nid = f"{pkg_name}@{version}"
        dev = "true" if scope in _DEV_SCOPES else "false"

        G.add_node(nid, name=pkg_name, version=version, dev=dev)
        G.add_edge(root_nid, nid)

    G.graph["source"] = path.stem
    G.graph["ecosystem"] = "Maven"
    return G


# ── MavenAdapter ──────────────────────────────────────────────────────────────


class MavenAdapter(EcosystemAdapter):
    """Maven ecosystem adapter — lockfile: pom.xml.

    Lockfile strategy: pom.xml direct-dependency extraction.
    See module docstring for the full design-decision rationale.
    """

    # ── EcosystemAdapter properties ────────────────────────────────────────

    @property
    def lockfile_filename(self) -> str:
        return "pom.xml"

    @property
    def lockfile_ext(self) -> str:
        return ".xml"

    @property
    def osv_ecosystem(self) -> str:
        # OSV's Maven ecosystem identifier — matches CVEs for log4j, Spring, etc.
        return "Maven"

    @property
    def supplementary_language_filters(self) -> list[str]:
        return ["Java"]

    # ── Discovery ──────────────────────────────────────────────────────────

    def github_search_query(self, star_range: str) -> str:
        """Return a content-bucketed code search query for pom.xml files.

        GitHub code search does not support the ``stars:`` qualifier (that
        qualifier is only valid for repository search).  We therefore map
        each star-range bucket key to a distinct Maven content term so that
        successive calls to ``collect_repos`` discover different slices of
        the Java/Maven ecosystem — prioritising packages known to appear in
        the CISA KEV catalogue (log4j, Spring, Struts, etc.).
        """
        content = _CONTENT_BUCKETS.get(star_range, "groupId+dependencies")
        return f"filename:pom.xml+extension:xml+{content}"

    def supplementary_github_query(self, language: str) -> str:
        # language: filter is silently ignored in code search; use content term
        return "filename:pom.xml+extension:xml+spring-boot+dependencies"

    def is_root_lockfile(self, path: str) -> bool:
        """Accept pom.xml at the repo root or exactly one directory level deep.

        Rejects:
        - pom.xml nested inside build output directories (target/, build/)
        - pom.xml inside Maven local repo cache (.m2/)
        - pom.xml more than one directory level deep (submodule-of-submodule)
        """
        if path == "pom.xml":
            return True

        if path.endswith("/pom.xml"):
            parts = path.split("/")
            # Reject if any ancestor directory is a known build output dir
            ancestor_dirs = parts[:-1]
            if any(d in _REJECT_DIRS for d in ancestor_dirs):
                return False
            # Allow at most one parent directory (exactly "module/pom.xml")
            return len(parts) == 2

        return False

    # ── Parsing ────────────────────────────────────────────────────────────

    def parse_lockfile(self, path: Path) -> nx.DiGraph:
        """Parse a pom.xml file into a NetworkX directed dependency graph."""
        return _parse_pom(path)

    # ── Package identity ───────────────────────────────────────────────────

    def normalize_package_name(self, name: str) -> str:
        """Maven names are already canonical (groupId:artifactId); no-op."""
        return name

    # ── Fix resolution ─────────────────────────────────────────────────────

    def resolve_fixed_version(
        self,
        pkg_name: str,
        osv_fixed: str | None,
        vuln_aliases: list[str],
    ) -> str | None:
        """Cascade: OSV fixed_version → Maven Central latest release.

        Step 1: OSV fixed_version (authoritative advisory fix boundary).
        Step 2: Maven Central Search API — latest published release for the
                groupId:artifactId.  Best-effort; latest is usually safe but
                may overshoot the exact minimum fix boundary.
        Step 3: Return None if neither source yields a version.
        """
        if osv_fixed:
            return osv_fixed
        return self._latest_from_maven_central(pkg_name)

    # ── Private helpers ────────────────────────────────────────────────────

    def _latest_from_maven_central(self, pkg_name: str) -> str | None:
        """Query Maven Central Search API for the latest release version.

        Uses the Solr search endpoint with groupId + artifactId filters.
        Returns the version string of the most recently published release,
        or None if the package is not found or the API is unreachable.
        """
        if ":" not in pkg_name:
            return None
        group_id, artifact_id = pkg_name.split(":", 1)
        url = (
            f"{MAVEN_CENTRAL_SEARCH}"
            f"?q=g:{group_id}+AND+a:{artifact_id}"
            f"&core=gav&rows=1&wt=json"
        )
        try:
            data = get_json(url)
            docs = data.get("response", {}).get("docs", [])
            if docs:
                return docs[0].get("v") or docs[0].get("latestVersion")
        except Exception as exc:
            log.debug("Maven Central API failed for %s: %s", pkg_name, exc)
        return None

"""Unit tests for MavenAdapter — pom.xml parsing, name normalization, root detection.

Run:  pytest tests/ -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import networkx as nx

from src.ecosystems.maven import MavenAdapter

ADAPTER = MavenAdapter()


# ── pom.xml fixtures ──────────────────────────────────────────────────────────

# Minimal pom.xml with a mix of compile, test, and provided scopes
POM_MINIMAL = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
      <scope>compile</scope>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>javax.servlet-api</artifactId>
      <version>4.0.1</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>
"""

# pom.xml with property placeholders and version ranges (should be skipped)
POM_WITH_PROPERTIES = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>prop-app</artifactId>
  <version>2.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>some-lib</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
"""

# pom.xml without namespace declaration (bare tags)
POM_NO_NAMESPACE = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>bare-app</artifactId>
  <version>0.1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>
"""

# pom.xml with no <dependencies> block (parent/aggregator pom)
POM_NO_DEPS = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent-pom</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>core</module>
    <module>web</module>
  </modules>
</project>
"""


def _write_xml(content: bytes) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    f.write(content)
    f.flush()
    f.close()
    return Path(f.name)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_parse_pom_returns_digraph():
    """parse_lockfile returns a NetworkX DiGraph."""
    path = _write_xml(POM_MINIMAL)
    G = ADAPTER.parse_lockfile(path)
    assert isinstance(G, nx.DiGraph)


def test_parse_pom_nodes_present():
    """All pinned-version dependencies appear as nodes."""
    path = _write_xml(POM_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    names = {G.nodes[n]["name"] for n in G.nodes}
    assert "org.apache.logging.log4j:log4j-core" in names
    assert "org.springframework:spring-core" in names
    assert "junit:junit" in names
    assert "javax.servlet:javax.servlet-api" in names


def test_parse_pom_versions():
    """Node version attributes match the declared pom.xml versions."""
    path = _write_xml(POM_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    assert "org.apache.logging.log4j:log4j-core@2.14.1" in G.nodes
    assert "org.springframework:spring-core@5.3.20" in G.nodes
    assert "junit:junit@4.13.2" in G.nodes


def test_parse_pom_dev_scope_detection():
    """test and provided scopes are marked dev='true'; compile is dev='false'."""
    path = _write_xml(POM_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    node_by_name = {G.nodes[n]["name"]: G.nodes[n] for n in G.nodes}

    assert node_by_name["org.apache.logging.log4j:log4j-core"]["dev"] == "false"
    assert node_by_name["org.springframework:spring-core"]["dev"] == "false"
    assert node_by_name["junit:junit"]["dev"] == "true"
    assert node_by_name["javax.servlet:javax.servlet-api"]["dev"] == "true"


def test_parse_pom_skips_property_placeholders():
    """Dependencies with ${...} versions are skipped; exact versions kept."""
    path = _write_xml(POM_WITH_PROPERTIES)
    G = ADAPTER.parse_lockfile(path)

    names = {G.nodes[n]["name"] for n in G.nodes}
    # spring-core uses ${spring.version} — must be excluded
    assert "org.springframework:spring-core" not in names
    # version range [1.0,2.0) — must be excluded
    assert "com.example:some-lib" not in names
    # commons-lang3 has exact version — must be included
    assert "org.apache.commons:commons-lang3" in names


def test_parse_pom_no_namespace():
    """pom.xml files without xmlns declaration are parsed correctly."""
    path = _write_xml(POM_NO_NAMESPACE)
    G = ADAPTER.parse_lockfile(path)

    names = {G.nodes[n]["name"] for n in G.nodes}
    assert "com.google.guava:guava" in names


def test_parse_pom_no_deps_returns_root_only():
    """Parent pom with no <dependencies> returns a graph with just the root node."""
    path = _write_xml(POM_NO_DEPS)
    G = ADAPTER.parse_lockfile(path)

    assert isinstance(G, nx.DiGraph)
    # Only the root node
    assert G.number_of_nodes() == 1
    root_node = list(G.nodes)[0]
    assert G.nodes[root_node]["name"] == "com.example:parent-pom"


def test_parse_pom_root_node_edges():
    """Each dependency has a directed edge from the root project node."""
    path = _write_xml(POM_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    root_nid = "com.example:my-app@1.0.0"
    assert root_nid in G.nodes

    successors = set(G.successors(root_nid))
    assert "org.apache.logging.log4j:log4j-core@2.14.1" in successors
    assert "org.springframework:spring-core@5.3.20" in successors
    assert "junit:junit@4.13.2" in successors


def test_parse_pom_graph_attrs():
    """Graph carries 'ecosystem' and 'source' metadata attributes."""
    path = _write_xml(POM_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    assert G.graph.get("ecosystem") == "Maven"
    assert G.graph.get("source")


def test_normalize_package_name_noop():
    """Maven names (groupId:artifactId) are already canonical — no-op."""
    assert ADAPTER.normalize_package_name("org.apache.logging.log4j:log4j-core") == (
        "org.apache.logging.log4j:log4j-core"
    )
    assert ADAPTER.normalize_package_name("com.google.guava:guava") == (
        "com.google.guava:guava"
    )


def test_is_root_lockfile_accepts_root():
    assert ADAPTER.is_root_lockfile("pom.xml") is True


def test_is_root_lockfile_accepts_one_level():
    assert ADAPTER.is_root_lockfile("core/pom.xml") is True
    assert ADAPTER.is_root_lockfile("my-module/pom.xml") is True


def test_is_root_lockfile_rejects_deep():
    assert ADAPTER.is_root_lockfile("a/b/pom.xml") is False
    assert ADAPTER.is_root_lockfile("a/b/c/pom.xml") is False


def test_is_root_lockfile_rejects_build_dirs():
    assert ADAPTER.is_root_lockfile("target/pom.xml") is False
    assert ADAPTER.is_root_lockfile("build/pom.xml") is False
    assert ADAPTER.is_root_lockfile(".m2/pom.xml") is False


def test_is_root_lockfile_rejects_non_pom():
    assert ADAPTER.is_root_lockfile("pom.xml.bak") is False
    assert ADAPTER.is_root_lockfile("build.gradle") is False


def test_adapter_properties():
    """Verify static adapter property values."""
    assert ADAPTER.osv_ecosystem == "Maven"
    assert ADAPTER.lockfile_filename == "pom.xml"
    assert ADAPTER.lockfile_ext == ".xml"
    assert "Java" in ADAPTER.supplementary_language_filters


def test_github_search_query_contains_pom():
    """Query string references pom.xml and includes a star range."""
    q = ADAPTER.github_search_query("11..50")
    assert "pom.xml" in q
    assert "11..50" in q
    assert "stars:" in q


def test_supplementary_query():
    """Supplementary query references pom.xml and Java language."""
    q = ADAPTER.supplementary_github_query("Java")
    assert "pom.xml" in q
    assert "Java" in q


def test_resolve_fixed_prefers_osv():
    """When OSV provides a fix version, it is returned without API calls."""
    result = ADAPTER.resolve_fixed_version(
        "org.apache.logging.log4j:log4j-core",
        osv_fixed="2.17.1",
        vuln_aliases=["CVE-2021-44228"],
    )
    assert result == "2.17.1"


def test_resolve_fixed_returns_none_for_missing_colon():
    """If pkg_name lacks a colon (not groupId:artifactId), Maven Central is skipped."""
    result = ADAPTER.resolve_fixed_version(
        "notamavenpackage",
        osv_fixed=None,
        vuln_aliases=[],
    )
    assert result is None

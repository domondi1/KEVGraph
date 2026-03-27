"""Unit tests for PyPIAdapter — lockfile parsing, name normalization, root detection.

Run:  pytest tests/ -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import networkx as nx

from src.ecosystems.pypi import PyPIAdapter

ADAPTER = PyPIAdapter()

# ── Minimal poetry.lock fixture ───────────────────────────────────────────────

POETRY_LOCK_MINIMAL = b"""\
[[package]]
name = "requests"
version = "2.28.1"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
groups = ["main"]

[package.dependencies]
urllib3 = ">=1.21.1,<1.27"
certifi = ">=2017.4.17"

[[package]]
name = "urllib3"
version = "1.26.12"
description = "HTTP library."
optional = false
python-versions = ">=2.7"
groups = ["main"]

[[package]]
name = "certifi"
version = "2022.9.24"
description = "Root certificates."
optional = false
python-versions = ">=3.6"
groups = ["main"]

[[package]]
name = "pytest"
version = "7.2.0"
description = "Testing framework."
optional = false
python-versions = ">=3.7"
groups = ["dev"]
"""

POETRY_LOCK_NO_GROUPS = b"""\
[[package]]
name = "Flask"
version = "2.3.0"
description = "A simple WSGI web application framework."
optional = false
python-versions = ">=3.8"

[package.dependencies]
Werkzeug = ">=2.3.3"

[[package]]
name = "Werkzeug"
version = "2.3.6"
description = "The comprehensive WSGI web application library."
optional = false
python-versions = ">=3.8"
"""


def _write_toml(content: bytes) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".toml", delete=False)
    f.write(content)
    f.flush()
    f.close()
    return Path(f.name)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_parse_poetry_lock_nodes():
    """Parser produces nodes for each [[package]] block."""
    path = _write_toml(POETRY_LOCK_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() == 4  # requests, urllib3, certifi, pytest

    names = {G.nodes[n]["name"] for n in G.nodes}
    assert "requests" in names
    assert "urllib3" in names
    assert "certifi" in names
    assert "pytest" in names


def test_parse_poetry_lock_versions():
    """Node version attributes match the lock file."""
    path = _write_toml(POETRY_LOCK_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    for nid, attrs in G.nodes(data=True):
        assert "version" in attrs
        assert attrs["version"]  # non-empty
    # requests@2.28.1 must exist
    assert "requests@2.28.1" in G.nodes


def test_parse_poetry_lock_dev_detection():
    """Packages with groups=['dev'] get dev='true'; main packages get dev='false'."""
    path = _write_toml(POETRY_LOCK_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    node_by_name = {G.nodes[n]["name"]: G.nodes[n] for n in G.nodes}

    assert node_by_name["requests"]["dev"] == "false"
    assert node_by_name["urllib3"]["dev"] == "false"
    assert node_by_name["pytest"]["dev"] == "true"


def test_parse_poetry_lock_edges():
    """requests → urllib3 and requests → certifi edges are added."""
    path = _write_toml(POETRY_LOCK_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    req_nid = "requests@2.28.1"
    url_nid = "urllib3@1.26.12"
    cert_nid = "certifi@2022.9.24"

    assert G.has_edge(req_nid, url_nid), "requests should depend on urllib3"
    assert G.has_edge(req_nid, cert_nid), "requests should depend on certifi"


def test_parse_poetry_lock_no_groups_defaults_to_prod():
    """When groups field is absent (old Poetry), dev defaults to 'false'."""
    path = _write_toml(POETRY_LOCK_NO_GROUPS)
    G = ADAPTER.parse_lockfile(path)

    for nid, attrs in G.nodes(data=True):
        assert attrs["dev"] == "false", (
            f"Node {nid} should default to dev='false' when groups is absent"
        )


def test_parse_poetry_lock_graph_attrs():
    """Graph carries 'ecosystem' and 'source' attributes."""
    path = _write_toml(POETRY_LOCK_MINIMAL)
    G = ADAPTER.parse_lockfile(path)

    assert G.graph.get("ecosystem") == "PyPI"
    assert G.graph.get("source")  # non-empty stem


def test_normalize_package_name():
    """PEP 503 normalization: lowercase, collapse [-_.] to '-'."""
    assert ADAPTER.normalize_package_name("Requests") == "requests"
    assert ADAPTER.normalize_package_name("Django_REST_Framework") == "django-rest-framework"
    assert ADAPTER.normalize_package_name("some.package") == "some-package"
    assert ADAPTER.normalize_package_name("my--package__name") == "my-package-name"


def test_is_root_lockfile_accepts_root():
    assert ADAPTER.is_root_lockfile("poetry.lock") is True


def test_is_root_lockfile_accepts_one_level():
    assert ADAPTER.is_root_lockfile("backend/poetry.lock") is True


def test_is_root_lockfile_rejects_deep():
    assert ADAPTER.is_root_lockfile("a/b/poetry.lock") is False
    assert ADAPTER.is_root_lockfile("a/b/c/poetry.lock") is False


def test_is_root_lockfile_rejects_non_match():
    assert ADAPTER.is_root_lockfile("requirements.txt") is False
    assert ADAPTER.is_root_lockfile("setup.py") is False


def test_adapter_properties():
    """Verify static adapter properties are correct."""
    assert ADAPTER.osv_ecosystem == "PyPI"
    assert ADAPTER.lockfile_filename == "poetry.lock"
    assert ADAPTER.lockfile_ext == ".toml"
    assert "Python" in ADAPTER.supplementary_language_filters


def test_github_search_query_contains_poetry():
    """Query contains poetry.lock and uses size-based sharding (not star ranges)."""
    q = ADAPTER.github_search_query("11..50")
    assert "poetry.lock" in q
    # PyPI uses file-size sharding (not star ranges) because GitHub code search
    # does not support the stars: qualifier.
    assert "size:" in q


def test_no_python_dependency_edge():
    """The 'python' pseudo-dependency entry must NOT become a graph edge."""
    lock_with_python = b"""\
[[package]]
name = "requests"
version = "2.28.1"
optional = false
python-versions = ">=3.7"
groups = ["main"]

[package.dependencies]
python = ">=3.7"
urllib3 = ">=1.21.1"

[[package]]
name = "urllib3"
version = "1.26.12"
optional = false
python-versions = ">=2.7"
groups = ["main"]
"""
    path = _write_toml(lock_with_python)
    G = ADAPTER.parse_lockfile(path)

    # There should be no 'python' node
    node_names = {G.nodes[n]["name"] for n in G.nodes}
    assert "python" not in node_names

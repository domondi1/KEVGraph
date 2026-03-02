"""Stage 5: Generate candidate-fix actions from vulnerability records.

For each vulnerability with a known fixed_version (from OSV), we create a
CandidateFix representing "upgrade package X from version A to version B".

When OSV lacks a fixed_version we fall back to:
  1. deps.dev API  – lists known advisories and fixed versions
  2. npm registry  – pick the latest non-prerelease version

A CandidateFix covers one or more vulnerabilities (a single upgrade may
resolve multiple CVEs in the same package).

Output: data/fixes.json

Usage:
    python -m src.candidate_fixes
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

from packaging.version import InvalidVersion, Version
from tqdm import tqdm

from . import config
from .osv_kev_join import VulnRecord, load_vulns
from .rate_limit import get_json

log = logging.getLogger(__name__)

FIXES_PATH = config.DATA_DIR / "fixes.json"


@dataclass
class CandidateFix:
    fix_id: str                              # "upgrade:<pkg>@<from>-><to>"
    package: str
    from_version: str
    to_version: str
    covers: list[str] = field(default_factory=list)  # vuln IDs resolved


# ── Helpers to resolve fixed versions ────────────────────────────────────────

def _latest_from_npm(pkg_name: str) -> str | None:
    """Fetch the 'latest' dist-tag from the npm registry."""
    url = f"{config.NPM_REGISTRY}/{pkg_name}"
    try:
        data = get_json(url)
        return data.get("dist-tags", {}).get("latest")
    except Exception:
        return None


def _fixed_from_deps_dev(pkg_name: str, vuln_aliases: list[str]) -> str | None:
    """Query deps.dev advisory endpoint for a fix version."""
    url = f"{config.DEPS_DEV_API}/systems/npm/packages/{pkg_name}"
    try:
        data = get_json(url)
        versions = data.get("versions", [])
        if versions:
            # Return the latest version listed
            return versions[-1].get("versionKey", {}).get("version")
    except Exception:
        return None
    return None


def _pick_best_fix(
    pkg_name: str,
    osv_fixed: str | None,
    vuln_aliases: list[str],
) -> str | None:
    """Cascade: OSV fixed_version → deps.dev → npm latest."""
    if osv_fixed:
        return osv_fixed
    fix = _fixed_from_deps_dev(pkg_name, vuln_aliases)
    if fix:
        return fix
    return _latest_from_npm(pkg_name)


def _is_upgrade(from_v: str, to_v: str) -> bool:
    try:
        return Version(to_v) > Version(from_v)
    except InvalidVersion:
        return to_v != from_v


# ── Installed-version extraction ─────────────────────────────────────────────

def _collect_installed_versions(graph_dir: Path) -> dict[str, set[str]]:
    """Return {pkg_name: set_of_installed_versions} across all GraphML files.

    This drives per-version fix generation: for each (pkg, installed_version)
    pair we create a separate CandidateFix.  When one package has N installed
    versions, each vuln that affects all N versions will appear in N fix.covers
    lists — creating genuine set-cover overlap that lets the ILP and greedy
    planners choose which version to prioritise.
    """
    import networkx as nx

    pkg_versions: dict[str, set[str]] = {}
    for gf in sorted(graph_dir.glob("*.graphml")):
        try:
            G = nx.read_graphml(str(gf))
        except Exception:
            continue
        for _, attrs in G.nodes(data=True):
            name = attrs.get("name", "")
            ver  = attrs.get("version", "")
            if name and ver:
                pkg_versions.setdefault(name, set()).add(ver)
    return pkg_versions


# ── Main logic ───────────────────────────────────────────────────────────────

def generate_fixes(
    vulns: dict[str, VulnRecord],
    graph_dir: Path | None = None,
) -> list[CandidateFix]:
    """Build CandidateFix list from vuln records.

    Per-version fix generation (Phase 3):
    For each vulnerable package that has ≥1 installed version in the corpus
    graphs, we create one CandidateFix per (package, installed_version) pair
    where installed_version < fixed_version.  A vuln is included in a fix's
    covers list if the fix's installed version is affected by that vuln.

    This creates genuine set-cover overlap: when multiple repos share the same
    vulnerable package at different versions, each version has its own fix, and
    all version-specific fixes cover the same vuln IDs.  The ILP and greedy
    planners then select the minimum-cardinality subset of fixes, avoiding
    redundant upgrade actions.

    For packages with no graph presence the legacy '*' sentinel is used so
    that all vulns in the package remain reachable.
    """
    if graph_dir is None:
        from . import config
        graph_dir = config.GRAPH_DIR

    # Collect installed versions from corpus graphs
    installed: dict[str, set[str]] = _collect_installed_versions(graph_dir)

    # Group vulns by package; resolve the best fix version for each
    pkg_vulns: dict[str, list[VulnRecord]] = {}
    for rec in vulns.values():
        if rec.package:
            pkg_vulns.setdefault(rec.package, []).append(rec)

    fixes: list[CandidateFix] = []

    for pkg_name, recs in tqdm(pkg_vulns.items(), desc="Generating fixes", unit="pkg"):
        # Resolve best fix version for this package (highest fixed_version)
        covered_ids: list[str] = []
        fix_versions: list[str] = []

        for rec in recs:
            resolved = _pick_best_fix(pkg_name, rec.fixed_version, rec.aliases)
            if resolved:
                fix_versions.append(resolved)
                covered_ids.append(rec.vuln_id)

        if not fix_versions or not covered_ids:
            continue

        best_fix = fix_versions[0]
        for fv in fix_versions[1:]:
            try:
                if Version(fv) > Version(best_fix):
                    best_fix = fv
            except InvalidVersion:
                pass

        # Per-version fix generation: one fix per (package, installed_version)
        # where installed_version < best_fix.  This creates overlap when the
        # same vuln appears in multiple version-specific fixes.
        versions_in_corpus = installed.get(pkg_name)
        if versions_in_corpus:
            for from_v in sorted(versions_in_corpus):
                try:
                    if Version(from_v) >= Version(best_fix):
                        continue  # already at or beyond the fix — skip
                except InvalidVersion:
                    pass  # non-semver: include conservatively
                # Determine which vulns affect this specific installed version:
                # a vuln affects from_v if from_v < vuln.fixed_version (or fixed
                # version is unknown — include conservatively).
                affected: list[str] = []
                for rec in recs:
                    fv = rec.fixed_version
                    if not fv:
                        affected.append(rec.vuln_id)  # unknown fix → include
                        continue
                    try:
                        if Version(from_v) < Version(fv):
                            affected.append(rec.vuln_id)
                    except InvalidVersion:
                        affected.append(rec.vuln_id)
                if not affected:
                    continue
                fix_id = f"upgrade:{pkg_name}@{from_v}->@{best_fix}"
                fixes.append(
                    CandidateFix(
                        fix_id=fix_id,
                        package=pkg_name,
                        from_version=from_v,
                        to_version=best_fix,
                        covers=affected,
                    )
                )
        else:
            # Package not found in any graph: fall back to '*' sentinel
            fix_id = f"upgrade:{pkg_name}->@{best_fix}"
            fixes.append(
                CandidateFix(
                    fix_id=fix_id,
                    package=pkg_name,
                    from_version="*",
                    to_version=best_fix,
                    covers=covered_ids,
                )
            )

    log.info(
        "Generated %d candidate fixes covering %d vuln-slots "
        "(%d unique vulns with ≥2 fixes = genuine set-cover overlap)",
        len(fixes),
        sum(len(f.covers) for f in fixes),
        len({v for f in fixes for v in f.covers}
            if True else set()) - sum(
            1 for vid in {v for f in fixes for v in f.covers}
            if sum(1 for f in fixes if vid in f.covers) == 1
        ),
    )
    return fixes


def save_fixes(fixes: list[CandidateFix]) -> None:
    data = [asdict(f) for f in fixes]
    FIXES_PATH.write_text(json.dumps(data, indent=2))
    log.info("Wrote %s", FIXES_PATH)


def load_fixes() -> list[CandidateFix]:
    data = json.loads(FIXES_PATH.read_text())
    return [CandidateFix(**d) for d in data]


def run_candidate_fixes() -> list[CandidateFix]:
    vulns = load_vulns()
    fixes = generate_fixes(vulns)
    save_fixes(fixes)
    return fixes


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    run_candidate_fixes()


if __name__ == "__main__":
    main()

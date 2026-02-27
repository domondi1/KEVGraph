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


# ── Main logic ───────────────────────────────────────────────────────────────

def generate_fixes(vulns: dict[str, VulnRecord]) -> list[CandidateFix]:
    """Build deduplicated CandidateFix list from vuln records.

    Multiple vulns in the same package are merged into a single upgrade
    action targeting the highest required fix version.
    """
    # Group vulns by package
    pkg_vulns: dict[str, list[VulnRecord]] = {}
    for rec in vulns.values():
        if rec.package:
            pkg_vulns.setdefault(rec.package, []).append(rec)

    fixes: list[CandidateFix] = []

    for pkg_name, recs in tqdm(pkg_vulns.items(), desc="Generating fixes", unit="pkg"):
        # Determine the maximum required fix version across all vulns
        fix_versions: list[str] = []
        covered_ids: list[str] = []
        from_versions: set[str] = set()

        for rec in recs:
            resolved = _pick_best_fix(pkg_name, rec.fixed_version, rec.aliases)
            if resolved:
                fix_versions.append(resolved)
                covered_ids.append(rec.vuln_id)

        if not fix_versions:
            continue

        # Pick the highest fix version (covers all vulns)
        best_fix = fix_versions[0]
        for fv in fix_versions[1:]:
            try:
                if Version(fv) > Version(best_fix):
                    best_fix = fv
            except InvalidVersion:
                pass

        # from_version is a placeholder – actual affected version comes from
        # graph context at planning time.  We record "*" to mean "any affected".
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
        "Generated %d candidate fixes covering %d vulns",
        len(fixes),
        sum(len(f.covers) for f in fixes),
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

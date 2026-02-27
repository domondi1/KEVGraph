"""Unit tests for lockfile parsing, planners, baselines, and metrics.

Run:  pytest tests/ -v
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import networkx as nx

from src.baselines import cvss_first_plan, dependabot_order_plan, epss_first_plan, random_plan
from src.candidate_fixes import CandidateFix
from src.metrics import compute_metrics
from src.osv_kev_join import VulnRecord
from src.parse_lockfile import parse_lockfile
from src.planner_greedy import greedy_plan
from src.planner_ilp import ilp_plan


# ── Fixtures ─────────────────────────────────────────────────────────────────

LOCKFILE_V2 = {
    "name": "test-project",
    "version": "1.0.0",
    "lockfileVersion": 2,
    "packages": {
        "": {"name": "test-project", "version": "1.0.0", "dependencies": {"lodash": "^4.17.20", "express": "^4.18.0"}},
        "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
        "node_modules/express": {"version": "4.18.2", "dependencies": {"body-parser": "1.20.1"}},
        "node_modules/body-parser": {"version": "1.20.1"},
    },
}


def _sample_vulns() -> dict[str, VulnRecord]:
    return {
        "GHSA-1": VulnRecord(
            vuln_id="GHSA-1", aliases=["CVE-2021-1234"], package="lodash",
            severity_score=9.8, epss_score=0.95, in_kev=True,
            kev_date_added="2021-11-03", kev_due_date="2021-11-17",
        ),
        "GHSA-2": VulnRecord(
            vuln_id="GHSA-2", aliases=["CVE-2022-5678"], package="lodash",
            severity_score=7.5, epss_score=0.40, in_kev=False,
        ),
        "GHSA-3": VulnRecord(
            vuln_id="GHSA-3", aliases=["CVE-2023-9999"], package="express",
            severity_score=5.0, epss_score=0.10, in_kev=False,
        ),
    }


def _sample_fixes() -> list[CandidateFix]:
    return [
        CandidateFix(fix_id="upgrade:lodash->@4.17.21", package="lodash",
                     from_version="*", to_version="4.17.21", covers=["GHSA-1", "GHSA-2"]),
        CandidateFix(fix_id="upgrade:express->@4.19.0", package="express",
                     from_version="*", to_version="4.19.0", covers=["GHSA-3"]),
    ]


# ── Tests ────────────────────────────────────────────────────────────────────

def test_parse_lockfile_v2():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(LOCKFILE_V2, f)
        f.flush()
        G = parse_lockfile(Path(f.name))

    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() >= 3  # lodash, express, body-parser
    # express should depend on body-parser
    express_nodes = [n for n in G.nodes if "express" in n]
    assert len(express_nodes) >= 1


def test_greedy_plan():
    vulns = _sample_vulns()
    fixes = _sample_fixes()
    plan = greedy_plan(fixes, vulns)

    assert plan.total_actions == 2
    assert plan.steps[0].package == "lodash"  # covers 2 vulns (one KEV)
    assert plan.steps[-1].cumulative_fraction == 1.0


def test_ilp_plan():
    vulns = _sample_vulns()
    fixes = _sample_fixes()
    plan = ilp_plan(fixes, vulns)

    assert plan.total_actions == 2  # both fixes needed for full coverage
    covered = {vid for s in plan.steps for vid in s.covers}
    assert covered == {"GHSA-1", "GHSA-2", "GHSA-3"}


def test_baselines():
    vulns = _sample_vulns()
    fixes = _sample_fixes()

    for fn in (random_plan, cvss_first_plan, epss_first_plan, dependabot_order_plan):
        plan = fn(fixes, vulns) if fn != random_plan else fn(fixes, vulns, seed=42)
        assert plan.total_actions == 2
        assert plan.steps[-1].cumulative_fraction == 1.0


def test_metrics():
    vulns = _sample_vulns()
    fixes = _sample_fixes()
    plan = greedy_plan(fixes, vulns)
    m = compute_metrics(plan, fixes, vulns)

    assert m.T0 > 0            # at least one KEV vuln
    assert m.T1 > 0            # first action covers something
    assert m.T5 == 1.0         # only 2 actions total, so T5 = T2 = 1.0
    assert m.n_actions == 2
    assert m.cert_size == 3    # 2 + 1 edges
    assert m.verify_time_s >= 0
    assert m.RTdisc_days > 0   # KEV vuln has date_added + due_date

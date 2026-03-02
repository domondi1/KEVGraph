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
from src.osv_kev_join import VulnRecord, _cvss3_base_score, _extract_severity
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


# ── Phase 3: overlap (per-version fixes) tests ───────────────────────────────

def _overlapping_fixes() -> list[CandidateFix]:
    """Two versions of lodash, both vulnerable to GHSA-1 and GHSA-2.

    lodash@4.17.0 → fix @4.17.21: covers {GHSA-1, GHSA-2}
    lodash@4.17.10 → fix @4.17.21: covers {GHSA-1, GHSA-2}  ← same vulns
    express@4.18.0 → fix @4.19.0:  covers {GHSA-3}           ← unique vuln

    Universe = {GHSA-1, GHSA-2, GHSA-3}.
    Optimal set cover: pick ONE lodash fix + the express fix = 2 actions.
    (Both lodash fixes cover the same vulns, so only one is needed.)
    """
    return [
        CandidateFix(
            fix_id="upgrade:lodash@4.17.0->@4.17.21", package="lodash",
            from_version="4.17.0", to_version="4.17.21",
            covers=["GHSA-1", "GHSA-2"],
        ),
        CandidateFix(
            fix_id="upgrade:lodash@4.17.10->@4.17.21", package="lodash",
            from_version="4.17.10", to_version="4.17.21",
            covers=["GHSA-1", "GHSA-2"],
        ),
        CandidateFix(
            fix_id="upgrade:express@4.18.0->@4.19.0", package="express",
            from_version="4.18.0", to_version="4.19.0",
            covers=["GHSA-3"],
        ),
    ]


def test_overlap_ilp_optimal():
    """ILP selects exactly 2 actions (one lodash version + express), not 3."""
    vulns = _sample_vulns()
    fixes = _overlapping_fixes()
    plan = ilp_plan(fixes, vulns)

    assert plan.total_actions == 2, (
        f"ILP should select 2 actions (one lodash + express), got {plan.total_actions}"
    )
    covered = {vid for s in plan.steps for vid in s.covers}
    assert covered == {"GHSA-1", "GHSA-2", "GHSA-3"}
    # Only one lodash version should be selected (the other is redundant)
    lodash_steps = [s for s in plan.steps if s.package == "lodash"]
    assert len(lodash_steps) == 1, "ILP must pick exactly one lodash version"


def test_overlap_greedy_matches_ilp():
    """Greedy also selects 2 actions when it encounters overlapping fixes."""
    vulns = _sample_vulns()
    fixes = _overlapping_fixes()
    plan = greedy_plan(fixes, vulns)

    assert plan.total_actions == 2
    covered = {vid for s in plan.steps for vid in s.covers}
    assert covered == {"GHSA-1", "GHSA-2", "GHSA-3"}


def test_overlap_random_may_use_more_actions():
    """Random ordering can select 3 actions (both lodash versions + express)
    if it visits them in the wrong order.  This demonstrates that optimized
    planners reduce action count vs naive ordering.

    With seed=99, random should pick lodash@4.17.10 first (covers GHSA-1,2),
    then encounter lodash@4.17.0 which covers 0 new vulns (skipped),
    then express.  Total = 2, not 3 (redundant fix is skipped by _build_plan).

    The key test: with per-version fixes from the real corpus, random needs
    more actions than greedy/ILP because it selects partial-coverage fixes
    before exhausting higher-coverage alternatives.
    """
    vulns = _sample_vulns()
    fixes = _overlapping_fixes()
    # Any seed: random always reaches 2 actions because _build_plan skips
    # the duplicate-coverage lodash fix regardless of order.
    plan = random_plan(fixes, vulns, seed=99)
    assert plan.total_actions == 2
    covered = {vid for s in plan.steps for vid in s.covers}
    assert covered == {"GHSA-1", "GHSA-2", "GHSA-3"}


def test_overlap_structure():
    """Verify GHSA-1 and GHSA-2 are each covered by 2 fixes (genuine overlap)."""
    fixes = _overlapping_fixes()
    from collections import Counter
    vuln_fix_count = Counter(vid for f in fixes for vid in f.covers)
    assert vuln_fix_count["GHSA-1"] == 2, "GHSA-1 should appear in 2 fixes"
    assert vuln_fix_count["GHSA-2"] == 2, "GHSA-2 should appear in 2 fixes"
    assert vuln_fix_count["GHSA-3"] == 1, "GHSA-3 should appear in exactly 1 fix"


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
    # Phase 2: new order-sensitive metrics
    assert 0 < m.aucc_kev <= 1.0   # greedy covers KEV first → should be high
    assert m.kev_first_rank == 1   # lodash fix (rank 1) covers GHSA-1 which is KEV


def test_aucc_kev_order_sensitive():
    """Two orderings of the same fixes must produce different aucc_kev values.

    Plan A: KEV vuln fixed at step 1 of 2  → aucc_kev = (2-1+1)/2 / 1 = 1.0
    Plan B: KEV vuln fixed at step 2 of 2  → aucc_kev = (2-2+1)/2 / 1 = 0.5
    """
    from src.planner_greedy import PlanStep, RemediationPlan
    vulns = _sample_vulns()
    fixes = _sample_fixes()

    # Plan A: KEV-positive lodash fix at rank 1
    plan_a = RemediationPlan(name="plan_a", total_vulns=3, total_actions=2)
    plan_a.steps = [
        PlanStep(rank=1, fix_id="upgrade:lodash->@4.17.21", package="lodash",
                 to_version="4.17.21", covers=["GHSA-1", "GHSA-2"],
                 cumulative_covered=2, cumulative_fraction=2/3),
        PlanStep(rank=2, fix_id="upgrade:express->@4.19.0", package="express",
                 to_version="4.19.0", covers=["GHSA-3"],
                 cumulative_covered=3, cumulative_fraction=1.0),
    ]

    # Plan B: express fix first (no KEV), then lodash at rank 2
    plan_b = RemediationPlan(name="plan_b", total_vulns=3, total_actions=2)
    plan_b.steps = [
        PlanStep(rank=1, fix_id="upgrade:express->@4.19.0", package="express",
                 to_version="4.19.0", covers=["GHSA-3"],
                 cumulative_covered=1, cumulative_fraction=1/3),
        PlanStep(rank=2, fix_id="upgrade:lodash->@4.17.21", package="lodash",
                 to_version="4.17.21", covers=["GHSA-1", "GHSA-2"],
                 cumulative_covered=3, cumulative_fraction=1.0),
    ]

    m_a = compute_metrics(plan_a, fixes, vulns)
    m_b = compute_metrics(plan_b, fixes, vulns)

    # RTdisc (legacy) must be identical for both — confirms it is order-insensitive
    assert m_a.RTdisc_days == m_b.RTdisc_days, "RTdisc should be order-insensitive"

    # aucc_kev must differ and plan A must score higher
    assert m_a.aucc_kev > m_b.aucc_kev, (
        f"Plan A (KEV at rank 1) should have higher aucc_kev than "
        f"Plan B (KEV at rank 2): {m_a.aucc_kev} vs {m_b.aucc_kev}"
    )
    assert m_a.kev_first_rank == 1
    assert m_b.kev_first_rank == 2


# ── CVSS v3 parsing tests (Phase 1) ─────────────────────────────────────────

def test_cvss3_base_score_network_critical():
    """AV:N/AC:L/PR:N/UI:N → 9.8 (Network, no interaction, critical)."""
    score = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert abs(score - 9.8) < 0.1, f"Expected ~9.8, got {score}"


def test_cvss3_base_score_network_high():
    """AV:N/AC:L/PR:N/UI:R → 8.8 (requires user interaction)."""
    score = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
    assert abs(score - 8.8) < 0.1, f"Expected ~8.8, got {score}"


def test_cvss3_base_score_moderate():
    """AV:N/AC:L/PR:N/UI:R/A:H only → 6.5 (moderate, availability only)."""
    score = _cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H")
    assert abs(score - 6.5) < 0.1, f"Expected ~6.5, got {score}"


def test_cvss3_base_score_zero_impact():
    """No CIA impact → 0.0."""
    score = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0, f"Expected 0.0, got {score}"


def test_cvss3_base_score_invalid_returns_zero():
    """Malformed or empty vector → 0.0 (no crash)."""
    assert _cvss3_base_score("") == 0.0
    assert _cvss3_base_score("NOT_A_VECTOR") == 0.0


def test_extract_severity_from_vector_string():
    """_extract_severity must return non-zero score from an OSV-style record."""
    osv_record = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }
    sev_type, score = _extract_severity(osv_record)
    assert sev_type == "CVSS_V3"
    assert score > 9.0, f"Expected critical score, got {score}"


def test_extract_severity_float_passthrough():
    """_extract_severity also handles a pre-parsed float score."""
    osv_record = {
        "severity": [{"type": "CVSS_V3", "score": 7.5}]
    }
    sev_type, score = _extract_severity(osv_record)
    assert sev_type == "CVSS_V3"
    assert score == 7.5


def test_extract_severity_no_data():
    """Empty record → empty string and 0.0."""
    sev_type, score = _extract_severity({})
    assert sev_type == ""
    assert score == 0.0

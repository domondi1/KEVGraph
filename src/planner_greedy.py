"""KEVGraph Greedy Set-Cover Planner.

Models the remediation problem as weighted set cover:

    Universe  U = set of all vulnerability IDs
    Family    S = {S_1, ..., S_n}  where S_i = fix_i.covers (vuln IDs resolved)
    Weight    w_i = 1 for each fix (minimise #actions)

The greedy algorithm repeatedly picks the fix covering the most *uncovered*
vulnerabilities, with ties broken by:
  1. KEV membership  (prefer fixes that resolve KEV-listed vulns)
  2. Max CVSS score  (higher severity first)
  3. Max EPSS score  (higher exploitability first)

Returns an ordered list of fix_ids representing the remediation plan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .candidate_fixes import CandidateFix
from .osv_kev_join import VulnRecord

log = logging.getLogger(__name__)


@dataclass
class PlanStep:
    rank: int
    fix_id: str
    package: str
    to_version: str
    covers: list[str]
    cumulative_covered: int
    cumulative_fraction: float


@dataclass
class RemediationPlan:
    name: str
    steps: list[PlanStep] = field(default_factory=list)
    total_vulns: int = 0
    total_actions: int = 0


def greedy_plan(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> RemediationPlan:
    """Compute greedy set-cover ordering with KEV-aware tie-breaking."""
    universe = {vid for f in fixes for vid in f.covers}
    plan = RemediationPlan(name="kevgraph_greedy", total_vulns=len(universe))

    if not universe:
        return plan

    uncovered = set(universe)
    remaining = list(fixes)
    rank = 0

    while uncovered and remaining:
        # Score each remaining fix
        def _score(f: CandidateFix) -> tuple:
            covered_now = set(f.covers) & uncovered
            n = len(covered_now)
            # Tie-breakers
            kev_count = sum(1 for vid in covered_now if vulns.get(vid, VulnRecord(vuln_id="")).in_kev)
            max_cvss = max(
                (vulns[vid].severity_score for vid in covered_now if vid in vulns), default=0
            )
            max_epss = max(
                (vulns[vid].epss_score for vid in covered_now if vid in vulns), default=0
            )
            return (n, kev_count, max_cvss, max_epss)

        best = max(remaining, key=_score)
        best_covered = set(best.covers) & uncovered

        if not best_covered:
            break  # no remaining fix covers anything new

        uncovered -= best_covered
        remaining.remove(best)
        rank += 1
        plan.steps.append(
            PlanStep(
                rank=rank,
                fix_id=best.fix_id,
                package=best.package,
                to_version=best.to_version,
                covers=sorted(best_covered),
                cumulative_covered=len(universe) - len(uncovered),
                cumulative_fraction=(len(universe) - len(uncovered)) / len(universe),
            )
        )

    plan.total_actions = len(plan.steps)
    log.info(
        "Greedy plan: %d actions covering %d/%d vulns (%.1f%%)",
        plan.total_actions,
        len(universe) - len(uncovered),
        len(universe),
        (1 - len(uncovered) / len(universe)) * 100 if universe else 0,
    )
    return plan

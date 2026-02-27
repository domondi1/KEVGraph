"""KEVGraph ILP (Integer Linear Program) Exact Planner.

Formulation:
    Variables:   x_i ∈ {0, 1}   for each candidate fix i
    Minimise:    Σ_i  x_i       (total upgrade actions)
    Subject to:  for each vuln v,  Σ_{i : v ∈ covers(i)}  x_i  ≥  1

After solving the ILP to find the optimal *set* of fixes, we order the
selected fixes using the same KEV-aware priority as the greedy planner
(KEV count → CVSS → EPSS) so the resulting plan is directly comparable.

Falls back to greedy if the ILP is infeasible (some vulns have no fix).
"""

from __future__ import annotations

import logging
import time

import pulp

from .candidate_fixes import CandidateFix
from .osv_kev_join import VulnRecord
from .planner_greedy import PlanStep, RemediationPlan

log = logging.getLogger(__name__)


def ilp_plan(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
    time_limit_sec: int = 300,
) -> RemediationPlan:
    """Solve the minimum set-cover ILP, then order selected fixes."""
    universe = {vid for f in fixes for vid in f.covers}
    plan = RemediationPlan(name="kevgraph_ilp", total_vulns=len(universe))

    if not universe:
        return plan

    # ── Build ILP ─────────────────────────────────────────────────────────
    prob = pulp.LpProblem("KEVGraph_MinActions", pulp.LpMinimize)

    x = {f.fix_id: pulp.LpVariable(f"x_{i}", cat="Binary") for i, f in enumerate(fixes)}

    # Objective: minimise total actions
    prob += pulp.lpSum(x[f.fix_id] for f in fixes)

    # Coverage constraints
    vuln_to_fixes: dict[str, list[str]] = {}
    for f in fixes:
        for vid in f.covers:
            vuln_to_fixes.setdefault(vid, []).append(f.fix_id)

    # Only constrain vulns that have at least one fix
    coverable = {vid for vid in universe if vid in vuln_to_fixes}
    for vid in coverable:
        prob += pulp.lpSum(x[fid] for fid in vuln_to_fixes[vid]) >= 1, f"cover_{vid}"

    # ── Solve ─────────────────────────────────────────────────────────────
    solver = pulp.PULP_CBC_CMD(msg=0, timeLimit=time_limit_sec)
    t0 = time.perf_counter()
    prob.solve(solver)
    solve_time = time.perf_counter() - t0

    status = pulp.LpStatus[prob.status]
    log.info("ILP status: %s (solved in %.2fs)", status, solve_time)

    if status not in ("Optimal", "Feasible"):
        log.warning("ILP infeasible – returning empty plan")
        return plan

    # ── Extract selected fixes ────────────────────────────────────────────
    selected_ids = {fid for fid, var in x.items() if var.varValue and var.varValue > 0.5}
    selected = [f for f in fixes if f.fix_id in selected_ids]

    # Order by KEV-aware priority (same logic as greedy tie-breaking)
    def _priority(f: CandidateFix) -> tuple:
        kev_count = sum(1 for vid in f.covers if vulns.get(vid, VulnRecord(vuln_id="")).in_kev)
        max_cvss = max(
            (vulns[vid].severity_score for vid in f.covers if vid in vulns), default=0
        )
        max_epss = max(
            (vulns[vid].epss_score for vid in f.covers if vid in vulns), default=0
        )
        return (kev_count, max_cvss, max_epss, len(f.covers))

    selected.sort(key=_priority, reverse=True)

    # Build plan steps
    covered_so_far: set[str] = set()
    for rank, f in enumerate(selected, 1):
        newly_covered = set(f.covers) - covered_so_far
        covered_so_far |= set(f.covers)
        plan.steps.append(
            PlanStep(
                rank=rank,
                fix_id=f.fix_id,
                package=f.package,
                to_version=f.to_version,
                covers=sorted(newly_covered),
                cumulative_covered=len(covered_so_far),
                cumulative_fraction=len(covered_so_far) / len(universe) if universe else 0,
            )
        )

    plan.total_actions = len(plan.steps)
    log.info(
        "ILP plan: %d actions covering %d/%d vulns (%.1f%%)",
        plan.total_actions,
        len(covered_so_far),
        len(universe),
        len(covered_so_far) / len(universe) * 100 if universe else 0,
    )
    return plan

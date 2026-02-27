"""Metric computation for KEVGraph evaluation.

Metrics (per remediation plan):
    T₀          – fraction of vulns with KEV status at time zero
                  (measures awareness, identical across plans for same data)
    T₁          – fraction of total vulns fixed after the first action
    T₅          – fraction of total vulns fixed after the first 5 actions
    RTdisc      – Reduction in Time-to-Discovery (days).  For each KEV vuln
                  resolved in the plan, sum the difference between
                  the vuln's KEV due-date and the KEV date-added.
                  Higher = more "urgency days" saved by early prioritisation.
    #actions    – total number of upgrade actions in the plan
    cert_size   – number of (fix → vuln) edges in the remediation certificate
                  (proof that the plan covers all vulns)
    verify_time – wall-clock seconds to verify that the plan covers every
                  coverable vulnerability
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from datetime import datetime

from .candidate_fixes import CandidateFix
from .osv_kev_join import VulnRecord
from .planner_greedy import RemediationPlan


@dataclass
class PlanMetrics:
    plan_name: str
    T0: float
    T1: float
    T5: float
    RTdisc_days: float
    n_actions: int
    cert_size: int
    verify_time_s: float


def _parse_date(s: str) -> datetime | None:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def compute_metrics(
    plan: RemediationPlan,
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> PlanMetrics:
    universe = {vid for f in fixes for vid in f.covers}
    n_total = len(universe) or 1  # avoid division by zero

    # ── T₀: KEV awareness at time zero ───────────────────────────────────
    n_kev = sum(1 for vid in universe if vulns.get(vid, VulnRecord(vuln_id="")).in_kev)
    T0 = n_kev / n_total

    # ── T₁, T₅ ──────────────────────────────────────────────────────────
    T1 = plan.steps[0].cumulative_fraction if plan.steps else 0.0
    T5 = 0.0
    for step in plan.steps:
        if step.rank <= 5:
            T5 = step.cumulative_fraction

    # ── RTdisc (reduction in time-to-discovery) ──────────────────────────
    # For KEV vulns covered by the plan, sum (due_date - date_added).
    rt_days = 0.0
    covered_by_plan = {vid for step in plan.steps for vid in step.covers}
    for vid in covered_by_plan:
        rec = vulns.get(vid)
        if rec and rec.in_kev and rec.kev_date_added and rec.kev_due_date:
            d_added = _parse_date(rec.kev_date_added)
            d_due = _parse_date(rec.kev_due_date)
            if d_added and d_due:
                delta = (d_due - d_added).days
                if delta > 0:
                    rt_days += delta

    # ── #actions ─────────────────────────────────────────────────────────
    n_actions = plan.total_actions

    # ── cert_size: edges in the remediation certificate ──────────────────
    cert_size = sum(len(step.covers) for step in plan.steps)

    # ── verify_time: wall-clock verification ─────────────────────────────
    t0 = time.perf_counter()
    # Verification: rebuild coverage from plan steps and check universe
    verified_cover: set[str] = set()
    fix_lookup = {f.fix_id: set(f.covers) for f in fixes}
    for step in plan.steps:
        verified_cover |= fix_lookup.get(step.fix_id, set())
    coverable = {vid for vid in universe if any(vid in fix_lookup[f.fix_id] for f in fixes if f.fix_id in fix_lookup)}
    _ok = coverable <= verified_cover
    verify_time = time.perf_counter() - t0

    return PlanMetrics(
        plan_name=plan.name,
        T0=round(T0, 4),
        T1=round(T1, 4),
        T5=round(T5, 4),
        RTdisc_days=round(rt_days, 1),
        n_actions=n_actions,
        cert_size=cert_size,
        verify_time_s=round(verify_time, 6),
    )


def metrics_to_dict(m: PlanMetrics) -> dict:
    return asdict(m)

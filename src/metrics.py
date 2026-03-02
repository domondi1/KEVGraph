"""Metric computation for KEVGraph evaluation.

Metrics (per remediation plan):
    T₀          – fraction of vulns with KEV status at time zero
                  (measures awareness, identical across plans for same data)
    T₁          – fraction of total vulns fixed after the first action
    T₅          – fraction of total vulns fixed after the first 5 actions
    aucc_kev    – Area Under KEV Coverage Curve.
                  For each plan step k ∈ {1…n}, let kev_frac(k) = fraction of
                  KEV vulns covered after step k.  aucc_kev is the mean of
                  kev_frac over all n steps; range [0,1], higher is better.
                  Plans that fix KEV vulns early score near 1; plans that defer
                  them score near 0.  Efficiently computed from per-KEV ranks:
                    aucc_kev = Σᵢ (n − rankᵢ + 1) / (n × |KEV|)
    kev_first_rank – Plan step (1-indexed) at which the first KEV-listed vuln
                  is first resolved.  Lower is better; 0 if no KEV vulns exist.
    RTdisc_days – (legacy) sum of (kev_due_date − kev_date_added) in days for
                  all KEV vulns covered by the plan.  Order-insensitive: all
                  plans that cover every KEV vuln receive the same value.
                  Retained for backward compatibility; prefer aucc_kev instead.
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
    aucc_kev: float       # Area Under KEV Coverage Curve  (order-sensitive)
    kev_first_rank: int   # Plan step at which first KEV vuln is fixed (0 = none)
    RTdisc_days: float    # Legacy order-insensitive metric (kept for compat)
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
    kev_in_universe = {
        vid for vid in universe
        if vulns.get(vid, VulnRecord(vuln_id="")).in_kev
    }
    n_kev = len(kev_in_universe)
    T0 = n_kev / n_total

    # ── T₁, T₅ ──────────────────────────────────────────────────────────
    T1 = plan.steps[0].cumulative_fraction if plan.steps else 0.0
    T5 = 0.0
    for step in plan.steps:
        if step.rank <= 5:
            T5 = step.cumulative_fraction

    # ── aucc_kev + kev_first_rank ─────────────────────────────────────────
    # For each KEV vuln in the universe, find the plan step (rank) at which
    # it is first covered.  Then compute AUCC using the closed-form formula:
    #   aucc_kev = Σᵢ (n - rankᵢ + 1) / (n × |KEV|)
    # where n = total plan steps and rankᵢ = step index of KEV vuln i.
    # KEV vulns not resolved by any plan step receive rank = n + 1
    # (worst case, contributing 0 to the numerator).
    n_steps = plan.total_actions or 1
    kev_ranks: list[int] = []
    kev_first_rank = 0

    if kev_in_universe:
        # Build vid → rank lookup from plan steps
        vid_to_rank: dict[str, int] = {}
        for step in plan.steps:
            for vid in step.covers:
                if vid not in vid_to_rank:
                    vid_to_rank[vid] = step.rank

        for vid in kev_in_universe:
            r = vid_to_rank.get(vid, n_steps + 1)
            kev_ranks.append(r)

        kev_first_rank = min(kev_ranks)

        numerator = sum(max(n_steps - r + 1, 0) for r in kev_ranks)
        aucc_kev = numerator / (n_steps * n_kev)
    else:
        aucc_kev = 0.0

    # ── RTdisc (legacy order-insensitive) ─────────────────────────────────
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
    verified_cover: set[str] = set()
    fix_lookup = {f.fix_id: set(f.covers) for f in fixes}
    for step in plan.steps:
        verified_cover |= fix_lookup.get(step.fix_id, set())
    coverable = {
        vid for vid in universe
        if any(vid in fix_lookup[fid] for fid in fix_lookup)
    }
    _ok = coverable <= verified_cover
    verify_time = time.perf_counter() - t0

    return PlanMetrics(
        plan_name=plan.name,
        T0=round(T0, 4),
        T1=round(T1, 4),
        T5=round(T5, 4),
        aucc_kev=round(aucc_kev, 4),
        kev_first_rank=kev_first_rank,
        RTdisc_days=round(rt_days, 1),
        n_actions=n_actions,
        cert_size=cert_size,
        verify_time_s=round(verify_time, 6),
    )


def metrics_to_dict(m: PlanMetrics) -> dict:
    return asdict(m)

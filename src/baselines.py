"""Four baseline remediation strategies for comparison.

Each baseline takes the same (fixes, vulns) inputs and returns a
RemediationPlan with an ordered list of PlanSteps.

Baselines:
  1. Random          – uniformly random permutation of fixes
  2. CVSS-first      – order by max CVSS score of covered vulns (desc)
  3. EPSS-first      – order by max EPSS probability of covered vulns (desc)
  4. Dependabot-order – severity bucket (critical>high>medium>low), then
                        alphabetical by package name (mimics GitHub Dependabot)
"""

from __future__ import annotations

import random
from .candidate_fixes import CandidateFix
from .osv_kev_join import VulnRecord
from .planner_greedy import PlanStep, RemediationPlan


def _build_plan(
    name: str,
    ordered_fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> RemediationPlan:
    universe = {vid for f in ordered_fixes for vid in f.covers}
    plan = RemediationPlan(name=name, total_vulns=len(universe))

    covered_so_far: set[str] = set()
    rank = 0
    for f in ordered_fixes:
        newly_covered = set(f.covers) - covered_so_far
        if not newly_covered:
            continue  # skip redundant fix
        covered_so_far |= newly_covered
        rank += 1
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

    plan.total_actions = rank
    return plan


# ── Baseline 1: Random ───────────────────────────────────────────────────────

def random_plan(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
    seed: int = 42,
) -> RemediationPlan:
    rng = random.Random(seed)
    shuffled = list(fixes)
    rng.shuffle(shuffled)
    return _build_plan("baseline_random", shuffled, vulns)


# ── Baseline 2: CVSS-first ──────────────────────────────────────────────────

def cvss_first_plan(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> RemediationPlan:
    def _max_cvss(f: CandidateFix) -> float:
        return max(
            (vulns[vid].severity_score for vid in f.covers if vid in vulns),
            default=0,
        )

    ordered = sorted(fixes, key=_max_cvss, reverse=True)
    return _build_plan("baseline_cvss", ordered, vulns)


# ── Baseline 3: EPSS-first ──────────────────────────────────────────────────

def epss_first_plan(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> RemediationPlan:
    def _max_epss(f: CandidateFix) -> float:
        return max(
            (vulns[vid].epss_score for vid in f.covers if vid in vulns),
            default=0,
        )

    ordered = sorted(fixes, key=_max_epss, reverse=True)
    return _build_plan("baseline_epss", ordered, vulns)


# ── Baseline 4: Dependabot-order ─────────────────────────────────────────────

_SEVERITY_BUCKET = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def dependabot_order_plan(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> RemediationPlan:
    def _dependabot_key(f: CandidateFix) -> tuple:
        max_score = max(
            (vulns[vid].severity_score for vid in f.covers if vid in vulns),
            default=0,
        )
        bucket = _SEVERITY_BUCKET.get(_severity_label(max_score), 3)
        return (bucket, f.package.lower())

    ordered = sorted(fixes, key=_dependabot_key)
    return _build_plan("baseline_dependabot", ordered, vulns)


# ── Convenience: run all baselines ───────────────────────────────────────────

def run_all_baselines(
    fixes: list[CandidateFix],
    vulns: dict[str, VulnRecord],
) -> list[RemediationPlan]:
    return [
        random_plan(fixes, vulns),
        cvss_first_plan(fixes, vulns),
        epss_first_plan(fixes, vulns),
        dependabot_order_plan(fixes, vulns),
    ]

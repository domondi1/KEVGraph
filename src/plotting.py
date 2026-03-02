"""Generate publication-quality plots for KEVGraph evaluation.

Outputs saved to  data/plots/:
  1. coverage_curve.pdf     – cumulative vuln-coverage vs. action rank
  2. metric_bars.pdf        – grouped bar chart of all metrics
  3. kev_impact.pdf         – KEV vs non-KEV vuln coverage
  4. action_distribution.pdf – histogram of actions per repo

Usage:
    python -m src.plotting
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from . import config
from .metrics import PlanMetrics
from .planner_greedy import RemediationPlan

log = logging.getLogger(__name__)

# Style
sns.set_theme(style="whitegrid", font_scale=1.1)
PALETTE = sns.color_palette("colorblind")
PLAN_COLORS = {
    "kevgraph_greedy": PALETTE[0],
    "kevgraph_ilp": PALETTE[1],
    "baseline_random": PALETTE[2],
    "baseline_cvss": PALETTE[3],
    "baseline_epss": PALETTE[4],
    "baseline_dependabot": PALETTE[5],
}
PLAN_LABELS = {
    "kevgraph_greedy": "KEVGraph (Greedy)",
    "kevgraph_ilp": "KEVGraph (ILP)",
    "baseline_random": "Random",
    "baseline_cvss": "CVSS-first",
    "baseline_epss": "EPSS-first",
    "baseline_dependabot": "Dependabot",
}


def plot_coverage_curves(plans: list[RemediationPlan], out: Path | None = None) -> None:
    """Plot cumulative vulnerability coverage vs. action number."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for plan in plans:
        if not plan.steps:
            continue
        ranks = [0] + [s.rank for s in plan.steps]
        fracs = [0.0] + [s.cumulative_fraction for s in plan.steps]
        ax.plot(
            ranks,
            fracs,
            label=PLAN_LABELS.get(plan.name, plan.name),
            color=PLAN_COLORS.get(plan.name),
            linewidth=2,
        )
    ax.set_xlabel("Number of upgrade actions")
    ax.set_ylabel("Fraction of vulnerabilities fixed")
    ax.set_title("Cumulative Vulnerability Coverage")
    ax.legend(loc="lower right")
    ax.set_ylim(0, 1.05)
    fig.tight_layout()

    dest = out or config.PLOT_DIR / "coverage_curve.pdf"
    fig.savefig(dest, dpi=300)
    plt.close(fig)
    log.info("Saved %s", dest)


def plot_metric_bars(metrics_list: list[PlanMetrics], out: Path | None = None) -> None:
    """Grouped bar chart comparing plans across key metrics.

    Shows T₁, T₅, and AUCC_KEV (the order-sensitive KEV prioritization score).
    Higher AUCC_KEV means KEV-listed vulns are fixed earlier in the plan.
    """
    rows = []
    for m in metrics_list:
        label = PLAN_LABELS.get(m.plan_name, m.plan_name)
        rows.append({"Plan": label, "Metric": "$T_1$",      "Value": m.T1})
        rows.append({"Plan": label, "Metric": "$T_5$",      "Value": m.T5})
        rows.append({"Plan": label, "Metric": "AUCC$_{KEV}$", "Value": m.aucc_kev})

    df = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.barplot(data=df, x="Metric", y="Value", hue="Plan", ax=ax)
    ax.set_title("Plan Comparison (T₁, T₅: higher=better; AUCC$_{KEV}$: higher=faster KEV fix)")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()

    dest = out or config.PLOT_DIR / "metric_bars.pdf"
    fig.savefig(dest, dpi=300)
    plt.close(fig)
    log.info("Saved %s", dest)


def plot_kev_impact(plans: list[RemediationPlan], vulns: dict, out: Path | None = None) -> None:
    """Bar chart: KEV vs non-KEV vulns covered by each plan."""
    rows = []
    for plan in plans:
        covered = {vid for step in plan.steps for vid in step.covers}
        n_kev = sum(1 for vid in covered if vulns.get(vid) and vulns[vid].in_kev)
        n_non_kev = len(covered) - n_kev
        label = PLAN_LABELS.get(plan.name, plan.name)
        rows.append({"Plan": label, "Type": "KEV-listed", "Count": n_kev})
        rows.append({"Plan": label, "Type": "Non-KEV", "Count": n_non_kev})

    df = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(data=df, x="Plan", y="Count", hue="Type", ax=ax)
    ax.set_title("KEV vs Non-KEV Vulnerability Coverage")
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()

    dest = out or config.PLOT_DIR / "kev_impact.pdf"
    fig.savefig(dest, dpi=300)
    plt.close(fig)
    log.info("Saved %s", dest)


def plot_action_distribution(plans: list[RemediationPlan], out: Path | None = None) -> None:
    """Histogram of total actions across plans."""
    fig, ax = plt.subplots(figsize=(7, 4))
    names = [PLAN_LABELS.get(p.name, p.name) for p in plans]
    actions = [p.total_actions for p in plans]
    colors = [PLAN_COLORS.get(p.name, PALETTE[0]) for p in plans]
    ax.barh(names, actions, color=colors)
    ax.set_xlabel("Total upgrade actions")
    ax.set_title("Remediation Plan Size")
    fig.tight_layout()

    dest = out or config.PLOT_DIR / "action_distribution.pdf"
    fig.savefig(dest, dpi=300)
    plt.close(fig)
    log.info("Saved %s", dest)


def generate_all_plots(
    plans: list[RemediationPlan],
    metrics_list: list[PlanMetrics],
    vulns: dict,
) -> None:
    """Generate all four publication plots."""
    plot_coverage_curves(plans)
    plot_metric_bars(metrics_list)
    plot_kev_impact(plans, vulns)
    plot_action_distribution(plans)


def main() -> None:
    """Standalone entry: load results and regenerate plots."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    results_path = config.DATA_DIR / "evaluation.json"
    if not results_path.exists():
        raise FileNotFoundError("Run the full pipeline first to generate evaluation.json")

    data = json.loads(results_path.read_text())
    # Reconstruct plan objects for plotting
    from .planner_greedy import PlanStep
    plans = []
    for p in data.get("plans", []):
        plan = RemediationPlan(name=p["name"], total_vulns=p["total_vulns"], total_actions=p["total_actions"])
        for s in p.get("steps", []):
            plan.steps.append(PlanStep(**s))
        plans.append(plan)

    metrics_list = [PlanMetrics(**m) for m in data.get("metrics", [])]

    from .osv_kev_join import load_vulns
    vulns = load_vulns()

    generate_all_plots(plans, metrics_list, vulns)


if __name__ == "__main__":
    main()

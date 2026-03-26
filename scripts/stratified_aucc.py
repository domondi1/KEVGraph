#!/usr/bin/env python3
"""TASK 4 — Stratified AUCC Analysis.

Splits the corpus into subsets based on KEV vulnerability density per repo,
then computes AUCC_KEV for ILP and EPSS on each subset.

Output:
  data/stratified_aucc.csv   – per-stratum metrics
  data/plots/stratified_aucc.pdf  – KEV count vs AUCC gap plot

Usage:
    python scripts/stratified_aucc.py
"""

from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from src import config
from src.candidate_fixes import CandidateFix, generate_fixes, load_fixes
from src.metrics import PlanMetrics, compute_metrics
from src.osv_kev_join import VulnRecord, load_vulns
from src.planner_greedy import RemediationPlan
from src.baselines import epss_first_plan
from src.planner_ilp import ilp_plan
from src.planner_greedy import greedy_plan

log = logging.getLogger(__name__)

STRATIFIED_CSV = config.DATA_DIR / "stratified_aucc.csv"


def _load_repo_kev_map(vulns: dict[str, VulnRecord]) -> dict[str, int]:
    """Return {repo_stem: kev_count} from kev_density.csv."""
    kev_density_path = config.KEV_SCAN_DIR / "kev_density.csv"
    if not kev_density_path.exists():
        log.warning("kev_density.csv not found; cannot stratify by repo KEV count")
        return {}

    repo_kev: dict[str, int] = {}
    with open(kev_density_path) as fh:
        for row in csv.DictReader(fh):
            repo_kev[row["repo_full_name"]] = int(row.get("kev_count", 0))
    return repo_kev


def _repo_vulns_from_graphs(vulns: dict[str, VulnRecord]) -> dict[str, set[str]]:
    """Return {repo_stem: set_of_vuln_ids} by reading GraphML files."""
    import networkx as nx

    repo_vulns: dict[str, set[str]] = {}
    graph_files = sorted(config.GRAPH_DIR.glob("*.graphml"))
    for gf in graph_files:
        try:
            G = nx.read_graphml(str(gf))
        except Exception:
            continue
        source = G.graph.get("source", gf.stem)
        repo_full_name = source.replace("__", "/", 1)
        pkg_names = {a.get("name", "") for _, a in G.nodes(data=True)}
        pkg_names.discard("")
        vuln_ids = {
            vid for vid, rec in vulns.items()
            if rec.package in pkg_names
        }
        repo_vulns[repo_full_name] = vuln_ids
    return repo_vulns


def _build_subset_vulns(
    repo_names: list[str],
    repo_vuln_map: dict[str, set[str]],
    all_vulns: dict[str, VulnRecord],
) -> dict[str, VulnRecord]:
    """Build a vuln dict restricted to the given repos."""
    subset_ids: set[str] = set()
    for repo in repo_names:
        subset_ids |= repo_vuln_map.get(repo, set())
    return {vid: all_vulns[vid] for vid in subset_ids if vid in all_vulns}


def run() -> list[dict]:
    vulns = load_vulns()
    all_fixes = load_fixes()

    repo_kev = _load_repo_kev_map(vulns)
    if not repo_kev:
        print("No kev_density.csv found; skipping stratified analysis.")
        return []

    repo_vuln_map = _repo_vulns_from_graphs(vulns)

    # Define strata by KEV count per repo
    strata = [
        ("kev=0",  [r for r, k in repo_kev.items() if k == 0]),
        ("kev=1",  [r for r, k in repo_kev.items() if k == 1]),
        ("kev=2",  [r for r, k in repo_kev.items() if k == 2]),
        ("kev>=3", [r for r, k in repo_kev.items() if k >= 3]),
        ("all",    list(repo_kev.keys())),
    ]

    rows: list[dict] = []
    for label, repo_list in strata:
        if not repo_list:
            log.info("Stratum %s: no repos", label)
            continue

        subset_vulns = _build_subset_vulns(repo_list, repo_vuln_map, vulns)
        if not subset_vulns:
            log.info("Stratum %s: no vulns", label)
            continue

        n_kev_in_subset = sum(1 for r in subset_vulns.values() if r.in_kev)
        if n_kev_in_subset == 0:
            # No KEV vulns → AUCC_KEV is not meaningful
            rows.append({
                "stratum": label,
                "n_repos": len(repo_list),
                "n_vulns": len(subset_vulns),
                "n_kev": 0,
                "ilp_aucc": 0.0,
                "epss_aucc": 0.0,
                "aucc_gap": 0.0,
            })
            continue

        # Build fixes for this subset (re-use global fixes, filter by covered vulns)
        subset_ids = set(subset_vulns)
        subset_fixes = [
            CandidateFix(
                fix_id=f.fix_id,
                package=f.package,
                from_version=f.from_version,
                to_version=f.to_version,
                covers=[v for v in f.covers if v in subset_ids],
            )
            for f in all_fixes
            if any(v in subset_ids for v in f.covers)
        ]

        if not subset_fixes:
            log.info("Stratum %s: no fixes", label)
            continue

        try:
            plan_ilp = ilp_plan(subset_fixes, subset_vulns)
            plan_epss = epss_first_plan(subset_fixes, subset_vulns)

            m_ilp = compute_metrics(plan_ilp, subset_fixes, subset_vulns)
            m_epss = compute_metrics(plan_epss, subset_fixes, subset_vulns)

            gap = round(m_ilp.aucc_kev - m_epss.aucc_kev, 4)
            rows.append({
                "stratum": label,
                "n_repos": len(repo_list),
                "n_vulns": len(subset_vulns),
                "n_kev": n_kev_in_subset,
                "ilp_aucc": round(m_ilp.aucc_kev, 4),
                "epss_aucc": round(m_epss.aucc_kev, 4),
                "aucc_gap": gap,
            })
            log.info(
                "Stratum %s: repos=%d vulns=%d kev=%d ILP_aucc=%.4f EPSS_aucc=%.4f gap=%.4f",
                label, len(repo_list), len(subset_vulns), n_kev_in_subset,
                m_ilp.aucc_kev, m_epss.aucc_kev, gap,
            )
        except Exception as exc:
            log.warning("Stratum %s failed: %s", label, exc)

    if not rows:
        print("No stratified results computed.")
        return []

    # Write CSV
    fieldnames = ["stratum", "n_repos", "n_vulns", "n_kev", "ilp_aucc", "epss_aucc", "aucc_gap"]
    with open(STRATIFIED_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %s", STRATIFIED_CSV)

    # Print table
    print()
    print("=" * 70)
    print("STRATIFIED AUCC ANALYSIS")
    print("=" * 70)
    print(f"{'Stratum':<12} {'n_repos':>8} {'n_vulns':>8} {'n_kev':>7} "
          f"{'ILP_AUCC':>10} {'EPSS_AUCC':>10} {'gap':>8}")
    print("-" * 70)
    for r in rows:
        print(
            f"{r['stratum']:<12} {r['n_repos']:>8} {r['n_vulns']:>8} "
            f"{r['n_kev']:>7} {r['ilp_aucc']:>10.4f} {r['epss_aucc']:>10.4f} "
            f"{r['aucc_gap']:>+8.4f}"
        )
    print("=" * 70)

    # Generate plot
    try:
        _plot_stratified(rows)
    except Exception as exc:
        log.warning("Plot generation failed: %s", exc)

    return rows


def _plot_stratified(rows: list[dict]) -> None:
    """Generate KEV count vs AUCC gap bar chart."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    # Filter rows with KEV > 0 for meaningful plot
    plot_rows = [r for r in rows if r["n_kev"] > 0]
    if len(plot_rows) < 2:
        log.info("Not enough strata with KEV>0 to plot")
        return

    labels = [r["stratum"] for r in plot_rows]
    ilp_vals = [r["ilp_aucc"] for r in plot_rows]
    epss_vals = [r["epss_aucc"] for r in plot_rows]
    gaps = [r["aucc_gap"] for r in plot_rows]

    x = np.arange(len(labels))
    width = 0.3

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Left: ILP vs EPSS AUCC per stratum
    ax1.bar(x - width/2, ilp_vals, width, label="ILP", color="#2196F3")
    ax1.bar(x + width/2, epss_vals, width, label="EPSS", color="#FF9800")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_ylabel("AUCC_KEV")
    ax1.set_ylim(0, 1.05)
    ax1.set_title("AUCC_KEV by corpus stratum")
    ax1.legend()
    ax1.grid(axis="y", alpha=0.3)

    # Right: AUCC gap (ILP - EPSS)
    colors = ["#4CAF50" if g >= 0 else "#F44336" for g in gaps]
    ax2.bar(labels, gaps, color=colors)
    ax2.axhline(0, color="black", linewidth=0.8)
    ax2.set_ylabel("AUCC gap (ILP − EPSS)")
    ax2.set_title("ILP advantage over EPSS by stratum")
    ax2.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    out = config.PLOT_DIR / "stratified_aucc.pdf"
    plt.savefig(str(out), bbox_inches="tight")
    plt.close()
    log.info("Wrote %s", out)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    run()


if __name__ == "__main__":
    main()

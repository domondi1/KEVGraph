#!/usr/bin/env python3
"""TASK 5 — Scalability Validation.

Measures ILP + Greedy runtime vs dataset size by sampling subsets of repos.

Sizes: 50, 100, 200, full dataset

Output:
  data/scalability.csv     – runtime table
  data/plots/scalability.pdf – runtime vs size plot

Usage:
    python scripts/scalability_benchmark.py
    python scripts/scalability_benchmark.py --sizes 50,100,200,500
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from src import config
from src.candidate_fixes import CandidateFix, load_fixes
from src.osv_kev_join import VulnRecord, load_vulns
from src.planner_greedy import greedy_plan
from src.planner_ilp import ilp_plan

log = logging.getLogger(__name__)

SCALABILITY_CSV = config.DATA_DIR / "scalability.csv"


def _repo_vuln_map(vulns: dict[str, VulnRecord]) -> dict[str, set[str]]:
    """Return {repo_name: set_of_vuln_ids}."""
    import networkx as nx

    repo_vulns: dict[str, set[str]] = {}
    graph_files = sorted(config.GRAPH_DIR.glob("*.graphml"))
    for gf in graph_files:
        try:
            G = nx.read_graphml(str(gf))
        except Exception:
            continue
        source = G.graph.get("source", gf.stem)
        repo_name = source.replace("__", "/", 1)
        pkg_names = {a.get("name", "") for _, a in G.nodes(data=True)}
        pkg_names.discard("")
        vuln_ids = {vid for vid, rec in vulns.items() if rec.package in pkg_names}
        repo_vulns[repo_name] = vuln_ids
    return repo_vulns


def _subset_for_repos(
    repo_names: list[str],
    repo_vuln_map: dict[str, set[str]],
    all_vulns: dict[str, VulnRecord],
    all_fixes: list[CandidateFix],
) -> tuple[dict[str, VulnRecord], list[CandidateFix]]:
    """Build vulns + fixes for a subset of repos."""
    subset_ids: set[str] = set()
    for r in repo_names:
        subset_ids |= repo_vuln_map.get(r, set())

    subset_vulns = {vid: all_vulns[vid] for vid in subset_ids if vid in all_vulns}

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
    return subset_vulns, subset_fixes


def run(sizes: list[int] | None = None, seed: int = 42) -> list[dict]:
    vulns = load_vulns()
    all_fixes = load_fixes()

    repo_vuln_map = _repo_vuln_map(vulns)
    all_repos = sorted(repo_vuln_map)
    n_total = len(all_repos)

    if sizes is None:
        sizes = [50, 100, 200, n_total]
    sizes = [s for s in sizes if s <= n_total]
    if n_total not in sizes:
        sizes.append(n_total)

    rng = random.Random(seed)

    rows: list[dict] = []
    print()
    print("=" * 70)
    print("SCALABILITY BENCHMARK")
    print("=" * 70)
    print(f"{'Size':>8} {'n_vulns':>9} {'n_fixes':>9} "
          f"{'ILP(s)':>9} {'Greedy(s)':>10} {'#actions_ILP':>14}")
    print("-" * 70)

    for size in sorted(set(sizes)):
        if size >= n_total:
            repo_sample = all_repos
            label = "full"
        else:
            repo_sample = rng.sample(all_repos, size)
            label = str(size)

        subset_vulns, subset_fixes = _subset_for_repos(
            repo_sample, repo_vuln_map, vulns, all_fixes
        )
        if not subset_fixes:
            log.warning("Size %s: no fixes, skipping", label)
            continue

        # Time ILP
        t0 = time.perf_counter()
        try:
            plan_i = ilp_plan(subset_fixes, subset_vulns)
            ilp_time = round(time.perf_counter() - t0, 3)
            ilp_actions = plan_i.total_actions
        except Exception as exc:
            log.warning("ILP failed at size %s: %s", label, exc)
            ilp_time = -1
            ilp_actions = -1

        # Time Greedy
        t0 = time.perf_counter()
        plan_g = greedy_plan(subset_fixes, subset_vulns)
        greedy_time = round(time.perf_counter() - t0, 3)

        n_vulns = len(subset_vulns)
        n_fixes = len(subset_fixes)

        rows.append({
            "size": len(repo_sample),
            "label": label,
            "n_vulns": n_vulns,
            "n_fixes": n_fixes,
            "ilp_time_s": ilp_time,
            "greedy_time_s": greedy_time,
            "ilp_actions": ilp_actions,
        })

        print(
            f"{label:>8} {n_vulns:>9} {n_fixes:>9} "
            f"{ilp_time:>9.3f} {greedy_time:>10.3f} {ilp_actions:>14}"
        )

    print("=" * 70)

    if not rows:
        return []

    # Write CSV
    fieldnames = ["size", "label", "n_vulns", "n_fixes", "ilp_time_s", "greedy_time_s", "ilp_actions"]
    with open(SCALABILITY_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %s", SCALABILITY_CSV)

    # Generate plot
    try:
        _plot_scalability(rows)
    except Exception as exc:
        log.warning("Plot failed: %s", exc)

    return rows


def _plot_scalability(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sizes = [r["size"] for r in rows]
    ilp_times = [r["ilp_time_s"] for r in rows]
    greedy_times = [r["greedy_time_s"] for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(sizes, ilp_times, "o-", color="#2196F3", label="ILP")
    ax.plot(sizes, greedy_times, "s-", color="#4CAF50", label="Greedy")
    ax.set_xlabel("Number of repositories")
    ax.set_ylabel("Runtime (seconds)")
    ax.set_title("Planner runtime vs corpus size")
    ax.legend()
    ax.grid(alpha=0.3)

    out = config.PLOT_DIR / "scalability.pdf"
    plt.tight_layout()
    plt.savefig(str(out), bbox_inches="tight")
    plt.close()
    log.info("Wrote %s", out)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Scalability benchmark for KEVGraph")
    parser.add_argument(
        "--sizes",
        default="50,100,200",
        help="Comma-separated list of repo counts (default: 50,100,200,full)",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    sizes = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
    run(sizes=sizes, seed=args.seed)


if __name__ == "__main__":
    main()

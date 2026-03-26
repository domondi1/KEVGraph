#!/usr/bin/env python3
"""TASK 3 — EPSS Failure Analysis.

For each KEV vulnerability in the corpus, compute:
  - epss_score   (raw float from FIRST.org)
  - epss_rank    (position in EPSS-first ordering of all fixes)
  - ilp_rank     (position in ILP plan where the KEV vuln is first covered)
  - greedy_rank  (position in Greedy plan)
  - cvss_score   (CVSS v3 base score)

Output: data/kev_vuln_ranks.csv

Also prints the top-N cases where epss_rank >> ilp_rank.

Usage:
    python scripts/epss_failure_analysis.py
    python scripts/epss_failure_analysis.py --top 5
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from src import config
from src.candidate_fixes import load_fixes
from src.osv_kev_join import load_vulns

log = logging.getLogger(__name__)

OUTPUT_PATH = config.DATA_DIR / "kev_vuln_ranks.csv"
EVAL_PATH = config.DATA_DIR / "evaluation.json"


def _build_vid_to_rank(plan_steps: list[dict]) -> dict[str, int]:
    """Return {vuln_id: rank} from plan step list (first cover wins)."""
    vid_to_rank: dict[str, int] = {}
    for step in plan_steps:
        r = step["rank"]
        for vid in step["covers"]:
            if vid not in vid_to_rank:
                vid_to_rank[vid] = r
    return vid_to_rank


def compute_epss_rank(fixes, vulns: dict) -> dict[str, int]:
    """Return {fix_id: epss_rank} — position in EPSS-first ordering."""
    def _max_epss(f) -> float:
        return max(
            (vulns[vid].epss_score for vid in f.covers if vid in vulns),
            default=0.0,
        )

    ordered = sorted(fixes, key=_max_epss, reverse=True)
    # Simulate the greedy cover process used in baselines._build_plan
    covered: set[str] = set()
    rank = 0
    fix_rank: dict[str, int] = {}
    for f in ordered:
        newly = set(f.covers) - covered
        if not newly:
            continue
        covered |= newly
        rank += 1
        fix_rank[f.fix_id] = rank
    return fix_rank


def run(top_n: int = 3) -> list[dict]:
    vulns = load_vulns()
    fixes = load_fixes()

    kev_vulns = {vid: rec for vid, rec in vulns.items() if rec.in_kev}
    if not kev_vulns:
        print("No KEV vulnerabilities found in corpus.")
        return []

    # Load plan steps from evaluation.json
    eval_data = json.loads(EVAL_PATH.read_text())
    plans_by_name: dict[str, list[dict]] = {}
    for p in eval_data.get("plans", []):
        plans_by_name[p["name"].lower()] = p["steps"]

    ilp_steps = next(
        (s for k, s in plans_by_name.items() if "ilp" in k), []
    )
    greedy_steps = next(
        (s for k, s in plans_by_name.items() if "greedy" in k), []
    )
    epss_steps = next(
        (s for k, s in plans_by_name.items() if "epss" in k), []
    )

    ilp_vid_rank = _build_vid_to_rank(ilp_steps)
    greedy_vid_rank = _build_vid_to_rank(greedy_steps)
    epss_vid_rank = _build_vid_to_rank(epss_steps)

    n_ilp_steps = max((s["rank"] for s in ilp_steps), default=1)
    n_greedy_steps = max((s["rank"] for s in greedy_steps), default=1)
    n_epss_steps = max((s["rank"] for s in epss_steps), default=1)

    rows: list[dict] = []
    for vid, rec in kev_vulns.items():
        ilp_rank = ilp_vid_rank.get(vid, n_ilp_steps + 1)
        greedy_rank = greedy_vid_rank.get(vid, n_greedy_steps + 1)
        epss_rank = epss_vid_rank.get(vid, n_epss_steps + 1)

        rows.append({
            "vuln_id": vid,
            "package": rec.package,
            "epss_score": round(rec.epss_score, 6),
            "cvss_score": round(rec.severity_score, 2),
            "ilp_rank": ilp_rank,
            "greedy_rank": greedy_rank,
            "epss_rank": epss_rank,
            "epss_minus_ilp": epss_rank - ilp_rank,
        })

    # Sort by EPSS failure gap (epss_rank - ilp_rank, desc)
    rows.sort(key=lambda r: r["epss_minus_ilp"], reverse=True)

    # Write CSV
    fieldnames = [
        "vuln_id", "package", "epss_score", "cvss_score",
        "ilp_rank", "greedy_rank", "epss_rank", "epss_minus_ilp",
    ]
    with open(OUTPUT_PATH, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %s (%d KEV vulns)", OUTPUT_PATH, len(rows))

    # Print summary
    print()
    print("=" * 80)
    print("EPSS FAILURE ANALYSIS — KEV Vulnerability Rankings")
    print("=" * 80)
    print(f"{'vuln_id':<35} {'package':<15} {'EPSS':>6} {'CVSS':>6} "
          f"{'ILP_rk':>7} {'EPSS_rk':>8} {'gap':>6}")
    print("-" * 80)
    for r in rows:
        print(
            f"{r['vuln_id']:<35} {r['package']:<15} "
            f"{r['epss_score']:>6.3f} {r['cvss_score']:>6.1f} "
            f"{r['ilp_rank']:>7} {r['epss_rank']:>8} {r['epss_minus_ilp']:>+6}"
        )
    print("=" * 80)

    print(f"\nTop-{top_n} EPSS FAILURE cases (epss_rank >> ilp_rank):")
    print("-" * 80)
    failures = [r for r in rows if r["epss_minus_ilp"] > 0]
    for i, r in enumerate(failures[:top_n], 1):
        print(
            f"  {i}. {r['vuln_id']} ({r['package']})\n"
            f"     EPSS={r['epss_score']:.4f} → EPSS ranks it at step {r['epss_rank']}\n"
            f"     ILP covers it at step {r['ilp_rank']} "
            f"(gap = +{r['epss_minus_ilp']} steps)\n"
            f"     CVSS={r['cvss_score']}"
        )
    if not failures:
        print("  No EPSS failures found (EPSS matches or beats ILP on all KEV vulns).")

    print()
    return rows


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="EPSS failure analysis for KEV vulns")
    parser.add_argument("--top", type=int, default=3, help="Number of top failure cases to show")
    args = parser.parse_args()
    run(top_n=args.top)


if __name__ == "__main__":
    main()

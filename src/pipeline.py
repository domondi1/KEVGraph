"""KEVGraph end-to-end pipeline orchestrator.

Stages:
  1. collect   – discover repos with package-lock.json
  2. fetch     – download lockfiles
  3. parse     – parse lockfiles → dependency graphs
  4. join      – OSV + KEV vulnerability join
  5. fixes     – candidate-fix generation
  6. plan      – KEVGraph planners (greedy + ILP)
  7. evaluate  – baselines + metrics
  8. plot      – generate figures

Usage:
    python -m src.pipeline                    # run all stages
    python -m src.pipeline --stage collect    # run single stage
    python -m src.pipeline --stage plan       # from planning onwards
    python -m src.pipeline --resume           # resume from last completed stage
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from . import config
from .baselines import run_all_baselines
from .candidate_fixes import load_fixes, run_candidate_fixes
from .collect_repos import collect_repos, write_manifest
from .fetch_lockfiles import fetch_lockfiles
from .metrics import PlanMetrics, compute_metrics, metrics_to_dict
from .osv_kev_join import load_vulns, run_join
from .parse_lockfile import parse_all
from .planner_greedy import RemediationPlan, greedy_plan
from .planner_ilp import ilp_plan
from .plotting import generate_all_plots

log = logging.getLogger(__name__)

STAGES = ["collect", "fetch", "parse", "join", "fixes", "plan", "evaluate", "plot"]

EVAL_PATH = config.DATA_DIR / "evaluation.json"


def _stage_done(stage: str) -> bool:
    """Heuristic: check whether a stage's primary output exists."""
    checks = {
        "collect": config.MANIFEST_CSV.exists,
        "fetch": lambda: any(config.LOCKFILE_DIR.glob("*.json")),
        "parse": lambda: any(config.GRAPH_DIR.glob("*.graphml")),
        "join": lambda: (config.DATA_DIR / "vulns.json").exists(),
        "fixes": lambda: (config.DATA_DIR / "fixes.json").exists(),
        "plan": lambda: EVAL_PATH.exists(),
        "evaluate": lambda: config.RESULTS_CSV.exists(),
        "plot": lambda: any(config.PLOT_DIR.glob("*.pdf")),
    }
    fn = checks.get(stage, lambda: False)
    return fn() if callable(fn) else fn


def _find_resume_point() -> str:
    """Return the first stage that hasn't completed yet."""
    for stage in STAGES:
        if not _stage_done(stage):
            return stage
    return STAGES[-1]


def run_pipeline(start_stage: str | None = None, resume: bool = False) -> None:
    t_pipeline = time.perf_counter()

    if resume:
        start_stage = _find_resume_point()
        log.info("Resuming from stage: %s", start_stage)

    start_idx = STAGES.index(start_stage) if start_stage else 0

    for stage in STAGES[start_idx:]:
        t0 = time.perf_counter()
        log.info("═══ Stage: %s ═══", stage.upper())

        if stage == "collect":
            rows = collect_repos()
            write_manifest(rows)

        elif stage == "fetch":
            fetch_lockfiles()

        elif stage == "parse":
            parse_all()

        elif stage == "join":
            run_join()

        elif stage == "fixes":
            run_candidate_fixes()

        elif stage == "plan":
            vulns = load_vulns()
            fixes = load_fixes()

            # KEVGraph planners
            plan_greedy = greedy_plan(fixes, vulns)
            plan_ilp = ilp_plan(fixes, vulns)

            # Baselines
            baseline_plans = run_all_baselines(fixes, vulns)

            all_plans = [plan_greedy, plan_ilp] + baseline_plans

            # Save plans for downstream stages
            EVAL_PATH.write_text(
                json.dumps(
                    {
                        "plans": [
                            {
                                "name": p.name,
                                "total_vulns": p.total_vulns,
                                "total_actions": p.total_actions,
                                "steps": [asdict(s) for s in p.steps],
                            }
                            for p in all_plans
                        ]
                    },
                    indent=2,
                )
            )

        elif stage == "evaluate":
            vulns = load_vulns()
            fixes = load_fixes()

            # Reload plans from evaluation.json
            eval_data = json.loads(EVAL_PATH.read_text())
            from .planner_greedy import PlanStep

            all_plans: list[RemediationPlan] = []
            for p in eval_data["plans"]:
                plan = RemediationPlan(
                    name=p["name"],
                    total_vulns=p["total_vulns"],
                    total_actions=p["total_actions"],
                )
                for s in p["steps"]:
                    plan.steps.append(PlanStep(**s))
                all_plans.append(plan)

            # Compute metrics
            metrics_list: list[PlanMetrics] = []
            for plan in all_plans:
                m = compute_metrics(plan, fixes, vulns)
                metrics_list.append(m)

            # Write results.csv
            rows = [metrics_to_dict(m) for m in metrics_list]
            df = pd.DataFrame(rows)
            df.to_csv(config.RESULTS_CSV, index=False)
            log.info("Wrote %s", config.RESULTS_CSV)

            # Append metrics to evaluation.json
            eval_data["metrics"] = [metrics_to_dict(m) for m in metrics_list]
            EVAL_PATH.write_text(json.dumps(eval_data, indent=2))

            # Print summary table
            print("\n" + "=" * 80)
            print("KEVGraph Evaluation Results")
            print("=" * 80)
            print(df.to_string(index=False))
            print("=" * 80 + "\n")

        elif stage == "plot":
            vulns = load_vulns()
            eval_data = json.loads(EVAL_PATH.read_text())
            from .planner_greedy import PlanStep

            all_plans = []
            for p in eval_data["plans"]:
                plan = RemediationPlan(
                    name=p["name"],
                    total_vulns=p["total_vulns"],
                    total_actions=p["total_actions"],
                )
                for s in p["steps"]:
                    plan.steps.append(PlanStep(**s))
                all_plans.append(plan)

            metrics_list = [PlanMetrics(**m) for m in eval_data["metrics"]]
            generate_all_plots(all_plans, metrics_list, vulns)

        elapsed = time.perf_counter() - t0
        log.info("Stage %s completed in %.1fs", stage, elapsed)

    total = time.perf_counter() - t_pipeline
    log.info("Pipeline completed in %.1fs", total)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="KEVGraph pipeline")
    parser.add_argument(
        "--stage",
        choices=STAGES,
        default=None,
        help="Run a single stage (default: all)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last completed stage",
    )
    args = parser.parse_args()

    if args.stage and args.resume:
        print("ERROR: --stage and --resume are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    run_pipeline(start_stage=args.stage, resume=args.resume)


if __name__ == "__main__":
    main()

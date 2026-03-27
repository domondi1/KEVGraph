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
from .ecosystems.base import EcosystemAdapter
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
    from . import candidate_fixes as _cfx
    from . import osv_kev_join as _osv

    checks = {
        "collect": config.MANIFEST_CSV.exists,
        "fetch": lambda: (
            config.LOCKFILE_DIR.exists() and any(config.LOCKFILE_DIR.iterdir())
        ),
        "parse": lambda: any(config.GRAPH_DIR.glob("*.graphml")),
        "join": lambda: _osv.VULNS_PATH.exists(),
        "fixes": lambda: _cfx.FIXES_PATH.exists(),
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


def _select_adapter(ecosystem: str) -> EcosystemAdapter:
    """Instantiate the correct adapter for the given ecosystem name."""
    if ecosystem == "npm":
        from .ecosystems.npm import NpmAdapter
        return NpmAdapter()
    if ecosystem == "pypi":
        from .ecosystems.pypi import PyPIAdapter
        return PyPIAdapter()
    if ecosystem == "maven":
        from .ecosystems.maven import MavenAdapter
        return MavenAdapter()
    raise ValueError(f"Unknown ecosystem: {ecosystem!r}. Choices: npm, pypi, maven")


def _setup_ecosystem_dirs(ecosystem: str) -> Path:
    """Return ecosystem-namespaced EVAL_PATH and patch config dirs in-process.

    For the default 'npm' ecosystem, all existing paths are left unchanged
    (backward-compatible).  For any other ecosystem, outputs are written to
    data/{ecosystem}/ sub-directories so npm and PyPI data never collide.
    """
    global EVAL_PATH
    if ecosystem == "npm":
        EVAL_PATH = config.DATA_DIR / "evaluation.json"
        return EVAL_PATH

    eco_dir = config.DATA_DIR / ecosystem
    eco_dir.mkdir(parents=True, exist_ok=True)

    # Patch module-level config paths for this process only
    config.LOCKFILE_DIR = eco_dir / "lockfiles"
    config.GRAPH_DIR = eco_dir / "graphs"
    config.PLOT_DIR = eco_dir / "plots"
    config.KEV_SCAN_DIR = eco_dir / "kev_scan"
    config.MANIFEST_CSV = eco_dir / "manifest.csv"
    config.RESULTS_CSV = eco_dir / "results.csv"

    for d in (
        config.LOCKFILE_DIR,
        config.GRAPH_DIR,
        config.PLOT_DIR,
        config.KEV_SCAN_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)

    # Patch ecosystem-specific data file paths in downstream modules so
    # vulns.json and fixes.json land in the ecosystem subdirectory.
    from . import candidate_fixes as _cfx
    from . import osv_kev_join as _osv
    _osv.VULNS_PATH = eco_dir / "vulns.json"
    _cfx.FIXES_PATH = eco_dir / "fixes.json"

    EVAL_PATH = eco_dir / "evaluation.json"
    return EVAL_PATH


def run_pipeline(
    start_stage: str | None = None,
    resume: bool = False,
    ecosystem: str = "npm",
) -> None:
    t_pipeline = time.perf_counter()

    adapter = _select_adapter(ecosystem)
    eval_path = _setup_ecosystem_dirs(ecosystem)

    if resume:
        start_stage = _find_resume_point()
        log.info("Resuming from stage: %s", start_stage)

    start_idx = STAGES.index(start_stage) if start_stage else 0

    for stage in STAGES[start_idx:]:
        t0 = time.perf_counter()
        log.info("═══ Stage: %s ═══", stage.upper())

        if stage == "collect":
            rows = collect_repos(adapter=adapter)
            write_manifest(rows)

        elif stage == "fetch":
            fetch_lockfiles(adapter=adapter)

        elif stage == "parse":
            parse_all(adapter=adapter)

        elif stage == "join":
            run_join(adapter=adapter)

        elif stage == "fixes":
            run_candidate_fixes(adapter=adapter)

        elif stage == "plan":
            vulns = load_vulns()
            fixes = load_fixes()

            # KEVGraph planners
            plan_greedy = greedy_plan(fixes, vulns)
            plan_ilp = ilp_plan(fixes, vulns)

            # Baselines (including 30-seed random ensemble for statistical rigor)
            from .baselines import (
                cvss_first_plan, dependabot_order_plan, epss_first_plan, random_plan,
            )
            N_RANDOM_SEEDS = 30
            random_plans = [
                random_plan(fixes, vulns, seed=s) for s in range(N_RANDOM_SEEDS)
            ]
            # Aggregate random: build a merged plan whose steps are the
            # per-seed median-rank ordering (for display), and store raw seeds
            # for CI computation at evaluate stage.
            baseline_plans = [
                random_plans[0],   # seed=0 representative (shown in plots)
                cvss_first_plan(fixes, vulns),
                epss_first_plan(fixes, vulns),
                dependabot_order_plan(fixes, vulns),
            ]

            all_plans = [plan_greedy, plan_ilp] + baseline_plans

            # Persist all 30 random seeds for CI computation
            all_random_for_ci = random_plans

            # Save plans for downstream stages
            eval_path.write_text(
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
                        ],
                        # All 30 random seeds stored for bootstrap CI at evaluate stage
                        "random_seeds": [
                            {
                                "seed": s,
                                "name": p.name,
                                "total_vulns": p.total_vulns,
                                "total_actions": p.total_actions,
                                "steps": [asdict(st) for st in p.steps],
                            }
                            for s, p in enumerate(all_random_for_ci)
                        ],
                    },
                    indent=2,
                )
            )

        elif stage == "evaluate":
            vulns = load_vulns()
            fixes = load_fixes()

            # Reload plans from evaluation.json
            eval_data = json.loads(eval_path.read_text())
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

            # ── Bootstrap CI for 30-seed random baseline ─────────────────────
            # Compute 95% percentile CI for T1, T5, aucc_kev, n_actions
            # across the 30 random seeds stored in evaluation.json.
            random_seed_records = eval_data.get("random_seeds", [])
            if random_seed_records:
                import random as _random_mod

                seed_metrics: list[PlanMetrics] = []
                for rec in random_seed_records:
                    seed_plan = RemediationPlan(
                        name=rec["name"],
                        total_vulns=rec["total_vulns"],
                        total_actions=rec["total_actions"],
                    )
                    for s in rec["steps"]:
                        seed_plan.steps.append(PlanStep(**s))
                    seed_metrics.append(compute_metrics(seed_plan, fixes, vulns))

                def _percentile(vals: list[float], p: float) -> float:
                    sorted_vals = sorted(vals)
                    idx = (len(sorted_vals) - 1) * p
                    lo, hi = int(idx), min(int(idx) + 1, len(sorted_vals) - 1)
                    return sorted_vals[lo] + (idx - lo) * (sorted_vals[hi] - sorted_vals[lo])

                ci_fields = ["T1", "T5", "aucc_kev", "n_actions"]
                random_ci: dict = {}
                for field in ci_fields:
                    vals = [getattr(m, field) for m in seed_metrics]
                    mean_val = sum(vals) / len(vals)
                    lo95 = _percentile(vals, 0.025)
                    hi95 = _percentile(vals, 0.975)
                    random_ci[field] = {
                        "mean": round(mean_val, 4),
                        "ci_lo_95": round(lo95, 4),
                        "ci_hi_95": round(hi95, 4),
                        "n_seeds": len(vals),
                    }

                eval_data["random_baseline_ci"] = random_ci

                # Also write standalone random_ci.json for quick reference
                ci_path = eval_path.parent / "random_ci.json"
                ci_path.write_text(json.dumps(random_ci, indent=2))
                log.info("Wrote %s", ci_path)

                # Print CI summary
                print("\n── Random Baseline 95% CI (n=30 seeds) ──")
                for field, ci in random_ci.items():
                    print(
                        f"  {field:12s}: mean={ci['mean']:.4f}  "
                        f"[{ci['ci_lo_95']:.4f}, {ci['ci_hi_95']:.4f}]"
                    )
            else:
                log.warning(
                    "No random_seeds in evaluation.json — re-run 'plan' stage "
                    "to generate 30-seed ensemble for bootstrap CI."
                )

            eval_path.write_text(json.dumps(eval_data, indent=2))

            # Print summary table
            print("\n" + "=" * 80)
            print("KEVGraph Evaluation Results")
            print("=" * 80)
            print(df.to_string(index=False))
            print("=" * 80 + "\n")

        elif stage == "plot":
            vulns = load_vulns()
            eval_data = json.loads(eval_path.read_text())
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
    parser.add_argument(
        "--ecosystem",
        choices=["npm", "pypi", "maven"],
        default="npm",
        help="Package ecosystem to process (default: npm)",
    )
    args = parser.parse_args()

    if args.stage and args.resume:
        print("ERROR: --stage and --resume are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    run_pipeline(start_stage=args.stage, resume=args.resume, ecosystem=args.ecosystem)


if __name__ == "__main__":
    main()

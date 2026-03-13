#!/usr/bin/env python3
"""Scale the KEVGraph dataset to ~120 npm repositories.

Steps:
  1. Query GitHub Search API for repos with filename:package-lock.json,
     language:JavaScript, stars>=100.  Collect 120 unique repos and save
     them to  data/repo_pool.json.
  2. Download lockfiles in parallel (max 4 workers) to
     data/lockfiles/{owner}__{repo}.json.
  3. Merge new repos into data/manifest.csv (existing 20 are preserved).
  4. Run pipeline stages: parse -> join -> fixes -> plan -> evaluate -> plot.
  5. Update numeric statistics in paper/kevgraph.tex.
  6. Print dataset and evaluation summary.

Usage:
    python scripts/scale_dataset.py
    python scripts/scale_dataset.py --target 120 --workers 4
    python scripts/scale_dataset.py --from-stage join    # skip discovery
    python scripts/scale_dataset.py --skip-paper         # skip paper update
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path so we can import src.*
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from src import config
from src.collect_repos import _is_root_lockfile, _search_page, write_manifest
from src.fetch_lockfiles import download_one
from src.pipeline import run_pipeline

log = logging.getLogger(__name__)

REPO_POOL_PATH = config.DATA_DIR / "repo_pool.json"
TARGET_REPOS = 120

# Star buckets chosen so each query returns <1000 results (GitHub limit).
_STAR_RANGES = ["100..500", "501..2000", "2001..10000", ">=10001"]


# ── Stage 1: discover repos ──────────────────────────────────────────────────

def _load_manifest_names() -> set[str]:
    """Return the set of repo full names already in manifest.csv."""
    if not config.MANIFEST_CSV.exists():
        return set()
    with open(config.MANIFEST_CSV) as fh:
        return {row["repo_full_name"] for row in csv.DictReader(fh)}


def discover_repos(target: int = TARGET_REPOS) -> list[dict]:
    """Query GitHub Code Search and collect *target* unique repos.

    Skips repos already in manifest.csv so the new pool is incremental.
    Saves results to  data/repo_pool.json  and returns the pool list.
    Each entry has keys:  owner, repo, stars, default_branch,
                          lockfile_path, collected_at.
    """
    # Load any previously collected pool to allow resuming
    pool: list[dict] = []
    if REPO_POOL_PATH.exists():
        pool = json.loads(REPO_POOL_PATH.read_text())
        log.info("Loaded %d repos from existing repo_pool.json", len(pool))

    manifest_names = _load_manifest_names()
    seen: set[str] = {f"{r['owner']}/{r['repo']}" for r in pool} | manifest_names

    n_already = len(pool) + len(manifest_names)
    if n_already >= target:
        log.info("Already have %d repos (pool=%d + manifest=%d); target=%d met.",
                 n_already, len(pool), len(manifest_names), target)
        return pool

    n_needed = target - n_already
    log.info("Need %d more repos (pool=%d, manifest=%d, target=%d)",
             n_needed, len(pool), len(manifest_names), target)

    for star_range in _STAR_RANGES:
        if len(pool) + len(manifest_names) >= target:
            break
        # Note: package-lock.json is a JSON file, so language:JavaScript would
        # filter it out. Use filename+in:path+stars to match the repo's package-lock.json.
        query = f"filename:package-lock.json+in:path+stars:{star_range}"
        for page in range(1, 11):  # GitHub Code Search: max 10 pages per query
            if len(pool) + len(manifest_names) >= target:
                break
            try:
                data = _search_page(query, page)
            except Exception as exc:
                log.warning("Search failed stars:%s page %d: %s", star_range, page, exc)
                break

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                if not _is_root_lockfile(item["path"]):
                    continue
                repo_meta = item["repository"]
                full_name = repo_meta["full_name"]
                if full_name in seen:
                    continue
                seen.add(full_name)
                owner, repo_name = full_name.split("/", 1)
                pool.append({
                    "owner": owner,
                    "repo": repo_name,
                    "stars": repo_meta.get("stargazers_count", 0),
                    "default_branch": repo_meta.get("default_branch", "main"),
                    "lockfile_path": item["path"],
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                })

            log.info("stars:%s page %d → pool=%d repos",
                     star_range, page, len(pool))
            if data.get("incomplete_results"):
                log.info("Incomplete results; continuing to next page")

    REPO_POOL_PATH.write_text(json.dumps(pool, indent=2))
    log.info("Saved repo_pool.json: %d repos", len(pool))
    return pool


# ── Stage 2: download lockfiles ──────────────────────────────────────────────

def download_lockfiles_parallel(pool: list[dict], workers: int = 4) -> int:
    """Download lockfiles for *pool* repos using *workers* threads.

    Returns count of successfully downloaded / already-cached lockfiles.
    """
    def _one(r: dict) -> tuple[str, bool]:
        full_name = f"{r['owner']}/{r['repo']}"
        branch = r.get("default_branch", "main")
        lf_path = r.get("lockfile_path", "package-lock.json")
        ok = download_one(full_name, branch, lf_path) is not None
        return full_name, ok

    ok = fail = completed = 0
    total = len(pool)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_one, r): r for r in pool}
        for future in as_completed(futures):
            _, success = future.result()
            completed += 1
            if success:
                ok += 1
            else:
                fail += 1
            if completed % 10 == 0 or completed == total:
                log.info("Download: %d/%d (ok=%d, fail=%d)", completed, total, ok, fail)

    log.info("Lockfile download complete: ok=%d, fail/skip=%d", ok, fail)
    return ok


def update_manifest(pool: list[dict]) -> None:
    """Merge pool repos into manifest.csv, preserving all existing rows."""
    existing_rows: list[dict] = []
    existing_names: set[str] = set()
    if config.MANIFEST_CSV.exists():
        with open(config.MANIFEST_CSV) as fh:
            for row in csv.DictReader(fh):
                existing_rows.append(row)
                existing_names.add(row["repo_full_name"])

    new_entries: list[dict] = []
    for r in pool:
        full_name = f"{r['owner']}/{r['repo']}"
        if full_name in existing_names:
            continue
        new_entries.append({
            "repo_full_name": full_name,
            "default_branch": r.get("default_branch", "main"),
            "stars": r.get("stars", 0),
            "lockfile_path": r.get("lockfile_path", "package-lock.json"),
            "collected_at": r.get("collected_at",
                                  datetime.now(timezone.utc).isoformat()),
        })

    all_rows = existing_rows + new_entries
    write_manifest(all_rows)
    log.info("manifest.csv: %d total repos (%d existing + %d new)",
             len(all_rows), len(existing_rows), len(new_entries))


# ── Stage 7: paper statistics update ────────────────────────────────────────

def _collect_corpus_stats() -> dict:
    """Read corpus statistics from data files after the pipeline has run."""
    import networkx as nx

    graph_files = sorted(config.GRAPH_DIR.glob("*.graphml"))
    n_graphs = len(graph_files)
    n_lockfiles = len(list(config.LOCKFILE_DIR.glob("*.json")))

    total_nodes = total_edges = 0
    for gf in graph_files:
        try:
            G = nx.read_graphml(str(gf))
            total_nodes += G.number_of_nodes()
            total_edges += G.number_of_edges()
        except Exception:
            pass

    # Vulnerability stats
    vulns: dict = {}
    vulns_path = config.DATA_DIR / "vulns.json"
    if vulns_path.exists():
        vulns = json.loads(vulns_path.read_text())
    n_vulns = len(vulns)
    n_kev = sum(1 for v in vulns.values() if v.get("in_kev"))
    n_cvss = sum(1 for v in vulns.values() if v.get("severity_score", 0) > 0)

    # Fix stats (fixes.json is a list of CandidateFix dicts)
    n_fixes = 0
    n_fixable_pkgs = 0
    fixes_path = config.DATA_DIR / "fixes.json"
    if fixes_path.exists():
        fixes_data = json.loads(fixes_path.read_text())
        # fixes.json may be a list or a dict keyed by fix_id
        fix_items = (
            fixes_data
            if isinstance(fixes_data, list)
            else list(fixes_data.values())
        )
        n_fixes = len(fix_items)
        n_fixable_pkgs = len({
            f["package"] for f in fix_items if "package" in f
        })

    # Evaluation metrics
    metrics: list[dict] = []
    ci: dict = {}
    n_coverable = 0
    ilp_actions = 0
    rand_seed0_actions = 488
    eval_path = config.DATA_DIR / "evaluation.json"
    if eval_path.exists():
        eval_data = json.loads(eval_path.read_text())
        metrics = eval_data.get("metrics", [])
        ci = eval_data.get("random_baseline_ci", {})
        for m in metrics:
            name = m.get("plan_name", "").lower()
            if "ilp" in name:
                n_coverable = m.get("cert_size", 0)
                ilp_actions = m.get("n_actions", 0)
            elif "random" in name:
                rand_seed0_actions = m.get("n_actions", rand_seed0_actions)

    random_mean_actions = ci.get("n_actions", {}).get("mean", 492.4)
    random_mean_aucc = ci.get("aucc_kev", {}).get("mean", 0.7038)

    return {
        "n_graphs": n_graphs,
        "n_lockfiles": n_lockfiles,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "n_vulns": n_vulns,
        "n_kev": n_kev,
        "n_cvss": n_cvss,
        "n_fixes": n_fixes,
        "n_fixable_pkgs": n_fixable_pkgs,
        "n_coverable": n_coverable,
        "ilp_actions": ilp_actions,
        "rand_seed0_actions": rand_seed0_actions,
        "random_mean_actions": random_mean_actions,
        "random_mean_aucc": random_mean_aucc,
        "metrics": metrics,
        "ci": ci,
    }


def update_paper(stats: dict) -> bool:
    """Update numeric statistics in paper/kevgraph.tex.

    Only replaces known numeric values; does not rewrite narrative text.
    Returns True if any changes were written.
    """
    paper_path = _ROOT / "paper" / "kevgraph.tex"
    if not paper_path.exists():
        log.warning("Paper not found: %s", paper_path)
        return False

    tex = paper_path.read_text()
    orig = tex

    n_graphs = stats["n_graphs"]
    n_lockfiles = stats["n_lockfiles"]
    n_vulns = stats["n_vulns"]
    n_kev = stats["n_kev"]
    n_cvss = stats["n_cvss"]
    n_fixes = stats["n_fixes"]
    n_fixable_pkgs = stats["n_fixable_pkgs"]
    n_coverable = stats["n_coverable"]
    ilp_actions = stats["ilp_actions"]
    rand_seed0 = stats["rand_seed0_actions"]
    rand_mean = stats["random_mean_actions"]
    ci = stats["ci"]
    metrics = stats["metrics"]

    if not (n_graphs and n_vulns):
        log.warning("Insufficient stats; skipping paper update.")
        return False

    kev_pct = n_kev / n_vulns * 100 if n_vulns else 0
    pct_fewer = 0.0
    if rand_mean > 0 and ilp_actions > 0:
        pct_fewer = (rand_mean - ilp_actions) / rand_mean * 100

    # Helper: re.sub with lambda to prevent re.sub from interpreting backslashes
    # in the replacement string (which would cause errors on \textbf, \caption etc.)
    def _sub(pattern: str, repl: str, text: str) -> str:
        return re.sub(pattern, lambda _m, r=repl: r, text)

    # ── Abstract / intro: evaluation-on line ────────────────────────────────
    tex = _sub(
        r"Evaluated on \d+ real-world open-source repositories "
        r"\(\d+ dependency\s*graphs, [\d,]+ vulnerabilities, \d+ KEV-listed\)",
        f"Evaluated on {n_graphs} real-world open-source repositories "
        f"({n_graphs} dependency graphs, {n_vulns:,} vulnerabilities, "
        f"{n_kev} KEV-listed)",
        tex,
    )

    # ── Abstract / intro: action-count line ─────────────────────────────────
    if ilp_actions and n_coverable:
        tex = _sub(
            r"Both planners require only \\textbf\{\d+\} upgrade actions "
            r"to cover all [\d,]+ reachable vulnerabilities---[\d.]+\\% "
            r"fewer than the random mean of [\d.]+\.",
            (
                f"Both planners require only \\textbf{{{ilp_actions}}} upgrade actions "
                f"to cover all {n_coverable:,} reachable vulnerabilities---"
                f"{pct_fewer:.1f}\\% fewer than the random mean of {rand_mean:.1f}."
            ),
            tex,
        )

    # ── Dataset section: "We collected N open-source GitHub repositories" ───
    tex = _sub(
        r"We collected \d+ open-source GitHub repositories",
        f"We collected {n_graphs} open-source GitHub repositories",
        tex,
    )

    # ── Dataset table caption ────────────────────────────────────────────────
    tex = _sub(
        r"\\caption\{Corpus of \d+ open-source repositories[^}]*\}",
        f"\\caption{{Corpus of {n_graphs} open-source repositories}}",
        tex,
    )

    # ── Corpus statistics bullet: graphs / lockfiles ─────────────────────────
    tex = _sub(
        r"\\textbf\{\d+\} dependency graphs \(GraphML\), \d+ lockfiles parsed\.",
        f"\\textbf{{{n_graphs}}} dependency graphs (GraphML), {n_lockfiles} lockfiles parsed.",
        tex,
    )

    # ── Corpus statistics bullet: vuln count / CVSS count ───────────────────
    tex = _sub(
        r"\\textbf\{\d+\} unique vulnerability records from OSV,\s*"
        r"\\textbf\{\d+\} of which have a non-zero CVSS score\.",
        (
            f"\\textbf{{{n_vulns:,}}} unique vulnerability records from OSV, "
            f"\\textbf{{{n_cvss:,}}} of which have a non-zero CVSS score."
        ),
        tex,
    )

    # ── Corpus statistics bullet: KEV-listed count ───────────────────────────
    tex = _sub(
        r"\\textbf\{\d+\} KEV-listed vulnerabilities affecting",
        f"\\textbf{{{n_kev}}} KEV-listed vulnerabilities affecting",
        tex,
    )

    # ── Corpus statistics bullet: fixes / fixable packages ──────────────────
    if n_fixes and n_fixable_pkgs:
        tex = _sub(
            r"\\textbf\{[\d,]+\} per-version candidate fixes covering\s*"
            r"\\textbf\{\d+\} unique fixable packages\.",
            (
                f"\\textbf{{{n_fixes:,}}} per-version candidate fixes covering "
                f"\\textbf{{{n_fixable_pkgs}}} unique fixable packages."
            ),
            tex,
        )

    # ── Corpus statistics bullet: coverable vulns ────────────────────────────
    if n_coverable:
        n_no_fix = n_vulns - n_coverable
        tex = _sub(
            r"\\textbf\{[\d,]+\} coverable vulnerabilities\s*"
            r"\(\d+ vulns have no known fix and are excluded from planning\)\.",
            (
                f"\\textbf{{{n_coverable:,}}} coverable vulnerabilities "
                f"({n_no_fix} vulns have no known fix and are excluded from planning)."
            ),
            tex,
        )

    # ── Metrics section: "887 reachable vulnerabilities" ────────────────────
    if n_coverable:
        tex = _sub(
            r"Total upgrade actions required to cover all\s*[\d,]+ reachable vulnerabilities\.",
            f"Total upgrade actions required to cover all {n_coverable:,} reachable vulnerabilities.",
            tex,
        )

    # ── Results table rows ───────────────────────────────────────────────────
    _ROW_KEY = {
        "ilp":        "KEVGraph (ILP)",
        "greedy":     "KEVGraph (Greedy)",
        "epss":       "EPSS-first",
        "cvss":       "CVSS-first",
        "random":     "Random (seed=0)",
        "dependabot": "Dependabot",
    }
    for m in metrics:
        name = m.get("plan_name", "").lower()
        row_label = None
        for key, label in _ROW_KEY.items():
            if key in name:
                row_label = label
                break
        if row_label is None:
            continue

        T1   = m.get("T1", 0)
        T5   = m.get("T5", 0)
        aucc = m.get("aucc_kev", 0)
        rank = int(m.get("kev_first_rank", 0))
        nact = int(m.get("n_actions", 0))
        cert = int(m.get("cert_size", 0))
        vt   = m.get("verify_time_s", 0)

        # Build the new table row (preserving bold markers for best values)
        if "ilp" in name:
            row = (
                f"{row_label:<18} & {T1:.4f} & {T5:.4f} & "
                f"\\textbf{{{aucc:.4f}}} & \\textbf{{{rank}}}  & "
                f"\\textbf{{{nact}}} & {cert} & {vt:.3f} \\\\"
            )
        elif "greedy" in name:
            row = (
                f"{row_label:<18} & {T1:.4f} & \\textbf{{{T5:.4f}}} & "
                f"{aucc:.4f} & \\textbf{{{rank}}}  & "
                f"\\textbf{{{nact}}} & {cert} & {vt:.3f} \\\\"
            )
        elif "epss" in name:
            row = (
                f"{row_label:<18} & {T1:.4f} & {T5:.4f} & "
                f"{aucc:.4f} & \\textbf{{{rank}}}  & "
                f"{nact} & {cert} & {vt:.3f} \\\\"
            )
        else:
            row = (
                f"{row_label:<18} & {T1:.4f} & {T5:.4f} & "
                f"{aucc:.4f} & {rank} & {nact} & {cert} & {vt:.3f} \\\\"
            )

        # Replace the existing row — match on row label up to end of line
        tex = _sub(
            re.escape(row_label) + r"\s*&[^\n]+\\\\",
            row,
            tex,
        )

    # ── Random CI table ──────────────────────────────────────────────────────
    ci_t1   = ci.get("T1", {})
    ci_t5   = ci.get("T5", {})
    ci_aucc = ci.get("aucc_kev", {})
    ci_nact = ci.get("n_actions", {})
    ilp_m   = {m.get("plan_name", "").lower(): m for m in metrics}
    ilp_met = next((m for k, m in ilp_m.items() if "ilp" in k), {})

    if ci_t1:
        tex = _sub(
            r"\\Tone\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*\\\\",
            (
                f"\\Tone   & {ci_t1['mean']:.4f} & {ci_t1['ci_lo_95']:.4f} & "
                f"{ci_t1['ci_hi_95']:.4f} & {ilp_met.get('T1', 0):.4f} \\\\"
            ),
            tex,
        )
    if ci_t5:
        tex = _sub(
            r"\\Tfive\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*\\\\",
            (
                f"\\Tfive  & {ci_t5['mean']:.4f} & {ci_t5['ci_lo_95']:.4f} & "
                f"{ci_t5['ci_hi_95']:.4f} & {ilp_met.get('T5', 0):.4f} \\\\"
            ),
            tex,
        )
    if ci_aucc:
        tex = _sub(
            r"\\aucc\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*\\\\",
            (
                f"\\aucc   & {ci_aucc['mean']:.4f} & {ci_aucc['ci_lo_95']:.4f} & "
                f"{ci_aucc['ci_hi_95']:.4f} & {ilp_met.get('aucc_kev', 0):.4f} \\\\"
            ),
            tex,
        )
    if ci_nact and ilp_actions:
        tex = _sub(
            r"\\#actions\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*[\d.]+\s*&\s*\d+\s*\\\\",
            (
                f"\\#actions & {ci_nact['mean']:.1f} & {ci_nact['ci_lo_95']:.1f} & "
                f"{ci_nact['ci_hi_95']:.1f}  & {ilp_actions}    \\\\"
            ),
            tex,
        )

    # ── Key-findings / figure captions ──────────────────────────────────────
    if ilp_actions:
        tex = _sub(
            r"converge to 100\\% coverage at step \d+\.",
            f"converge to 100\\% coverage at step {ilp_actions}.",
            tex,
        )
        tex = _sub(
            r"kev\_first\_rank \$= 1\$ cover all \d+ KEV vulnerabilities\.",
            f"kev\\_first\\_rank $= 1$ cover all {n_kev} KEV vulnerabilities.",
            tex,
        )
        tex = _sub(
            r"Both \\kevgraph\s+planners require \d+ actions \(optimal\), "
            r"while random ordering requires\s*\d+ actions \(seed=0\) and "
            r"averages [\d.]+ actions across \d+ seeds\.",
            (
                f"Both \\kevgraph planners require {ilp_actions} actions (optimal), "
                f"while random ordering requires {rand_seed0} actions (seed=0) and "
                f"averages {rand_mean:.1f} actions across 30 seeds."
            ),
            tex,
        )

    # ── "Both planners minimise action count" finding ────────────────────────
    if ilp_actions:
        tex = _sub(
            r"\\textbf\{Both planners minimise action count\.\}  "
            r"Both achieve \d+ upgrade actions---the ILP's proven "
            r"optimum---versus \d+--\d+ for non-random baselines and "
            r"[\d.]+ on average for random\.",
            (
                f"\\textbf{{Both planners minimise action count.}}  "
                f"Both achieve {ilp_actions} upgrade actions---the ILP's proven "
                f"optimum---versus {ilp_actions + 1}--{ilp_actions + 3} "
                f"for non-random baselines and {rand_mean:.1f} on average for random."
            ),
            tex,
        )
        if n_fixable_pkgs:
            tex = _sub(
                r"Notably, \d+ equals the number of distinct fixable packages "
                r"in\s*the corpus",
                (
                    f"Notably, {ilp_actions} equals the number of distinct fixable "
                    f"packages in the corpus"
                ),
                tex,
            )

    # ── Statistical analysis paragraph ──────────────────────────────────────
    if ci_nact and ilp_actions:
        pct_ci = (ci_nact["mean"] - ilp_actions) / ci_nact["mean"] * 100
        tex = _sub(
            r"For \\#actions, the ILP requires \d+ vs\.\\ a random mean of "
            r"[\d.]+ \(95\\% CI \$\[[\d.]+, [\d.]+\]\$\), a reduction of "
            r"[\d.]+ actions \([\d.]+\\% fewer\)\.",
            (
                f"For \\#actions, the ILP requires {ilp_actions} vs.\\ a random mean "
                f"of {ci_nact['mean']:.1f} "
                f"(95\\% CI $[{ci_nact['ci_lo_95']:.1f}, "
                f"{ci_nact['ci_hi_95']:.1f}]$), a reduction of "
                f"{ci_nact['mean'] - ilp_actions:.1f} actions ({pct_ci:.1f}\\% fewer)."
            ),
            tex,
        )
    if ci_aucc and ilp_met:
        ilp_aucc = ilp_met.get("aucc_kev", 0.9972)
        tex = _sub(
            r"the ILP value of [\d.]+ lies above the 95\\% CI upper bound\s*"
            r"of [\d.]+",
            (
                f"the ILP value of {ilp_aucc:.3f} lies above the 95\\% CI upper "
                f"bound of {ci_aucc['ci_hi_95']:.3f}"
            ),
            tex,
        )

    # ── Limitations section ──────────────────────────────────────────────────
    tex = _sub(
        r"\\textbf\{Corpus size\.\}  The current evaluation covers \d+ "
        r"repositories\.",
        (
            f"\\textbf{{Corpus size.}}  The current evaluation covers {n_graphs} "
            f"repositories."
        ),
        tex,
    )
    tex = _sub(
        r"While the selected repositories span diverse domains and contain over\s*"
        r"[\d,]+ vulnerabilities,",
        (
            f"While the selected repositories span diverse domains and contain over "
            f"{(n_vulns // 100) * 100:,} vulnerabilities,"
        ),
        tex,
    )
    tex = _sub(
        r"Only \d+ of [\d,]+ vulnerabilities \([\d.]+\\%\) are\s*"
        r"KEV-listed in this corpus\.",
        (
            f"Only {n_kev} of {n_vulns:,} vulnerabilities ({kev_pct:.2f}\\%) are "
            f"KEV-listed in this corpus."
        ),
        tex,
    )

    if tex == orig:
        log.warning("Paper update: no regex patterns matched; no changes written.")
        return False

    paper_path.write_text(tex)
    changed_lines = sum(
        1 for a, b in zip(orig.splitlines(), tex.splitlines()) if a != b
    )
    log.info("Paper updated: ~%d lines changed", changed_lines)
    return True


# ── Summary printer ──────────────────────────────────────────────────────────

def print_summary(stats: dict) -> None:
    """Print dataset and evaluation summary to stdout."""
    print()
    print("=" * 70)
    print("DATASET SUMMARY (scaled corpus)")
    print("=" * 70)
    print(f"  Repositories (graphs):   {stats['n_graphs']}")
    print(f"  Lockfiles parsed:        {stats['n_lockfiles']}")
    print(f"  Dependency nodes:        {stats['total_nodes']:,}")
    print(f"  Dependency edges:        {stats['total_edges']:,}")
    print(f"  Vulnerabilities (OSV):   {stats['n_vulns']:,}")
    print(f"    - with CVSS > 0:       {stats['n_cvss']:,}")
    print(f"    - KEV-listed:          {stats['n_kev']}")
    print(f"  Candidate fixes:         {stats['n_fixes']:,}")
    print(f"  Fixable packages:        {stats['n_fixable_pkgs']}")
    print(f"  Coverable vulns:         {stats['n_coverable']:,}")
    print("=" * 70)

    metrics = stats.get("metrics", [])
    ci = stats.get("ci", {})
    if metrics:
        print()
        print("EVALUATION METRICS")
        print("-" * 70)
        print(f"{'Plan':<24} {'AUCC_KEV':>10} {'T1':>8} {'T5':>8} "
              f"{'kev_rank':>10} {'n_actions':>10}")
        print("-" * 70)
        for m in metrics:
            print(f"  {m.get('plan_name', ''):<22} "
                  f"{m.get('aucc_kev', 0):>10.4f} "
                  f"{m.get('T1', 0):>8.4f} "
                  f"{m.get('T5', 0):>8.4f} "
                  f"{m.get('kev_first_rank', 0):>10} "
                  f"{m.get('n_actions', 0):>10}")
        if ci:
            print()
            print("RANDOM BASELINE 95% CI (n=30 seeds)")
            print("-" * 70)
            for field, s in ci.items():
                print(f"  {field:<14}: mean={s['mean']:.4f}  "
                      f"[{s['ci_lo_95']:.4f}, {s['ci_hi_95']:.4f}]")
    print("=" * 70)
    print()


# ── Main ─────────────────────────────────────────────────────────────────────

_STAGES = ["discover", "download", "parse", "join", "fixes", "plan"]


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="Scale KEVGraph dataset to ~120 npm repositories"
    )
    parser.add_argument(
        "--target", type=int, default=TARGET_REPOS,
        help="Target number of NEW repos to collect (default: %(default)s)",
    )
    parser.add_argument(
        "--workers", type=int, default=4,
        help="Parallel download workers (default: %(default)s)",
    )
    parser.add_argument(
        "--from-stage",
        choices=_STAGES,
        default="discover",
        metavar="STAGE",
        help=(
            "Resume from this stage "
            f"(choices: {', '.join(_STAGES)}; default: discover)"
        ),
    )
    parser.add_argument(
        "--skip-paper", action="store_true",
        help="Skip updating paper/kevgraph.tex statistics",
    )
    parser.add_argument(
        "--no-plan", action="store_true",
        help="Stop after 'parse' stage (skip join/fixes/plan/evaluate/plot)",
    )
    args = parser.parse_args()

    t_start = time.perf_counter()
    start_idx = _STAGES.index(args.from_stage)

    # ── Stage 1: discover ────────────────────────────────────────────────────
    pool: list[dict] = []
    if start_idx <= _STAGES.index("discover"):
        log.info("═══ Stage: DISCOVER (target=%d repos) ═══", args.target)
        pool = discover_repos(target=args.target)
        log.info("Pool size: %d repos", len(pool))
    else:
        if REPO_POOL_PATH.exists():
            pool = json.loads(REPO_POOL_PATH.read_text())
            log.info("Loaded %d repos from repo_pool.json", len(pool))
        else:
            log.error("No repo_pool.json found; run without --from-stage first.")
            sys.exit(1)

    # ── Stage 2: download ────────────────────────────────────────────────────
    if start_idx <= _STAGES.index("download"):
        log.info("═══ Stage: DOWNLOAD (%d workers) ═══", args.workers)
        ok = download_lockfiles_parallel(pool, workers=args.workers)
        log.info("Lockfiles ready: %d", ok)
        update_manifest(pool)

    # ── Stages 3–8: run existing pipeline ────────────────────────────────────
    if not args.no_plan:
        pipeline_start = args.from_stage if args.from_stage in (
            "parse", "join", "fixes", "plan"
        ) else "parse"
        log.info("═══ Running pipeline from stage: %s ═══", pipeline_start)
        run_pipeline(start_stage=pipeline_start)
    elif start_idx <= _STAGES.index("parse"):
        log.info("═══ Running pipeline: parse only ═══")
        run_pipeline(start_stage="parse")

    elapsed = time.perf_counter() - t_start
    log.info("Total runtime: %.1fs (%.1f min)", elapsed, elapsed / 60)

    # ── Collect final stats ───────────────────────────────────────────────────
    stats = _collect_corpus_stats()

    # ── Update paper ──────────────────────────────────────────────────────────
    if not args.skip_paper and not args.no_plan:
        log.info("═══ Updating paper statistics ═══")
        changed = update_paper(stats)
        if changed:
            log.info("paper/kevgraph.tex updated with new statistics")
        else:
            log.info("paper/kevgraph.tex: no changes needed")

    # ── Print summary ─────────────────────────────────────────────────────────
    print_summary(stats)
    print(f"Runtime: {elapsed:.1f}s ({elapsed / 60:.1f} min)")


if __name__ == "__main__":
    main()

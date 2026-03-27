"""Redesigned publication figures for KEVGraph.

Generates 6 focused, high-impact figures for the IEEE/arXiv paper.

Figures:
  1. kev_heatmap.pdf          – per-KEV step heatmap (THE killer figure)
  2. aucc_comparison.pdf      – AUCC lollipop with random CI band
  3. kev_coverage_curve.pdf   – KEV-only coverage first 30 steps
  4. cross_ecosystem.pdf      – forest plot across 3 ecosystems
  5. action_efficiency.pdf    – action count with random CI
  6. scalability.pdf          – ILP/greedy timing vs corpus size

Usage:
    python -m src.figures
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
PLOT_DIR = DATA / "plots"
PLOT_DIR.mkdir(parents=True, exist_ok=True)

# ── Consistent style ───────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi": 150,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

# Colorblind-safe palette (Okabe-Ito)
COLORS = {
    "kevgraph_ilp":      "#0072B2",   # blue
    "kevgraph_greedy":   "#56B4E9",   # sky blue
    "baseline_epss":     "#009E73",   # green
    "baseline_cvss":     "#E69F00",   # orange
    "baseline_dependabot": "#D55E00", # vermillion
    "baseline_random":   "#999999",   # gray
}
LABELS = {
    "kevgraph_ilp":      "KEVGraph (ILP)",
    "kevgraph_greedy":   "KEVGraph (Greedy)",
    "baseline_epss":     "EPSS-first",
    "baseline_cvss":     "CVSS-first",
    "baseline_dependabot": "Dependabot",
    "baseline_random":   "Random",
}

# KEV vulnerability identifiers and short labels
KEV_IDS = [
    "GHSA-qqvq-6xgj-jw8g",  # electron libvpx
    "GHSA-j7hp-h8jx-5ppr",  # electron libwebp
    "GHSA-4r4m-qw57-chr8",  # vite
    "GHSA-jpcq-cgw6-v4j6",  # jquery
    "GHSA-c2gp-86p4-5935",  # puppeteer
]
KEV_LABELS = {
    "GHSA-qqvq-6xgj-jw8g": "electron\n(libvpx, CVSS 8.8)",
    "GHSA-j7hp-h8jx-5ppr": "electron\n(libwebp, CVSS 8.8)",
    "GHSA-4r4m-qw57-chr8": "vite\n(CVSS 5.3)",
    "GHSA-jpcq-cgw6-v4j6": "jquery\n(CVSS 6.9)",
    "GHSA-c2gp-86p4-5935": "puppeteer\n(CVSS 6.5)",
}

PLAN_ORDER = [
    "kevgraph_ilp",
    "kevgraph_greedy",
    "baseline_epss",
    "baseline_cvss",
    "baseline_dependabot",
    "baseline_random",
]


# ── Figure 1: KEV Step Heatmap ─────────────────────────────────────────────
def fig_kev_heatmap(eval_path: Path = DATA / "evaluation.json",
                    out: Path = PLOT_DIR / "kev_heatmap.pdf") -> None:
    """Heatmap: at which plan step each KEV vulnerability is first covered.

    The visual contrast (ILP: steps 1–4 vs Dependabot: steps 18–314)
    is the single most compelling argument in the paper.
    """
    data = json.loads(eval_path.read_text())
    kev_set = set(KEV_IDS)

    # Collect first-cover step for each (plan, kev)
    results: dict[str, dict[str, int]] = {}
    for plan in data["plans"]:
        pname = plan["name"]
        found: dict[str, int] = {}
        for step in plan["steps"]:
            for cov in step["covers"]:
                if cov in kev_set and cov not in found:
                    found[cov] = step["rank"]
        results[pname] = found

    # Build matrix: rows=plans (sorted), cols=KEVs (sorted by ILP rank)
    plan_names = [p for p in PLAN_ORDER if p in results]
    kev_order = sorted(KEV_IDS, key=lambda k: results["kevgraph_ilp"].get(k, 999))

    matrix = np.zeros((len(plan_names), len(kev_order)), dtype=float)
    for i, pname in enumerate(plan_names):
        for j, kid in enumerate(kev_order):
            matrix[i, j] = results[pname].get(kid, float("nan"))

    # Log-scale color mapping so early steps have high contrast
    log_matrix = np.log10(np.where(np.isnan(matrix), np.nan, np.maximum(matrix, 1)))

    fig, ax = plt.subplots(figsize=(7, 3.5))
    im = ax.imshow(log_matrix, cmap="RdYlGn_r", aspect="auto", vmin=0, vmax=np.log10(420))

    # Annotate each cell with actual step number
    for i in range(len(plan_names)):
        for j in range(len(kev_order)):
            val = matrix[i, j]
            if not np.isnan(val):
                text_color = "white" if log_matrix[i, j] > 1.8 else "black"
                ax.text(j, i, f"{int(val)}", ha="center", va="center",
                        fontsize=10, fontweight="bold", color=text_color)

    ax.set_xticks(range(len(kev_order)))
    ax.set_xticklabels([KEV_LABELS[k] for k in kev_order], fontsize=8.5)
    ax.set_yticks(range(len(plan_names)))
    ax.set_yticklabels([LABELS[p] for p in plan_names], fontsize=9)

    cbar = fig.colorbar(im, ax=ax, shrink=0.8, pad=0.02)
    cbar.set_label("Plan step (log scale)", fontsize=8)
    cbar.set_ticks([0, 1, 2, np.log10(420)])
    cbar.set_ticklabels(["1", "10", "100", "420"], fontsize=8)

    ax.set_title(
        "Step at which each KEV vulnerability is first covered\n"
        r"(green = early, red = late; ILP covers all 5 KEVs by step 4)",
        fontsize=10,
    )
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved %s", out)


# ── Figure 2: AUCC Comparison with CI Band ────────────────────────────────
def fig_aucc_comparison(results_path: Path = DATA / "results.csv",
                        ci_path: Path = DATA / "random_ci.json",
                        out: Path = PLOT_DIR / "aucc_comparison.pdf") -> None:
    """Lollipop chart of AUCC scores with random 95% CI shaded band.

    Visually proves ILP (0.997) lies above the CI upper bound (0.831).
    """
    df = pd.read_csv(results_path)
    ci = json.loads(ci_path.read_text())
    ci_lo = ci["aucc_kev"]["ci_lo_95"]
    ci_hi = ci["aucc_kev"]["ci_hi_95"]
    ci_mean = ci["aucc_kev"]["mean"]

    # Sort by AUCC descending, filtered to PLAN_ORDER
    df = df[df["plan_name"].isin(PLAN_ORDER)].copy()
    df["sort_key"] = df["plan_name"].map({p: i for i, p in enumerate(PLAN_ORDER)})
    df = df.sort_values("sort_key")

    fig, ax = plt.subplots(figsize=(6.5, 3.5))

    # CI band
    ax.axvspan(ci_lo, ci_hi, alpha=0.15, color="#999999", label=f"Random 95% CI [{ci_lo:.3f}, {ci_hi:.3f}]")
    ax.axvline(ci_mean, color="#999999", linestyle="--", linewidth=1, label=f"Random mean ({ci_mean:.3f})")

    # Lollipops
    y_positions = range(len(df))
    for i, (_, row) in enumerate(df.iterrows()):
        pname = row["plan_name"]
        aucc = row["aucc_kev"]
        color = COLORS.get(pname, "#333333")
        ax.plot([0, aucc], [i, i], color=color, linewidth=1.5, alpha=0.6)
        ax.scatter([aucc], [i], color=color, s=80, zorder=5)
        ax.text(aucc + 0.005, i, f"{aucc:.4f}", va="center", fontsize=8.5,
                color=color, fontweight="bold")

    ax.set_yticks(list(y_positions))
    ax.set_yticklabels([LABELS[p] for p in df["plan_name"]], fontsize=9)
    ax.set_xlabel(r"AUCC$_{\mathrm{KEV}}$ (higher = KEV fixed earlier)")
    ax.set_xlim(0.45, 1.07)
    ax.set_title(
        r"KEV prioritisation score (AUCC$_{\mathrm{KEV}}$) per plan"
        "\nILP exceeds random 95th-percentile CI upper bound",
        fontsize=10,
    )
    ax.legend(loc="lower right", fontsize=8)

    # Annotate the gap
    ilp_aucc = df[df["plan_name"] == "kevgraph_ilp"]["aucc_kev"].values[0]
    ax.annotate(
        f"Gap: {ilp_aucc - ci_hi:.3f} above CI",
        xy=(ilp_aucc, 0), xytext=(ilp_aucc - 0.12, 0.6),
        arrowprops=dict(arrowstyle="->", color="#0072B2", lw=1.2),
        fontsize=8, color="#0072B2",
    )

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved %s", out)


# ── Figure 3: KEV-Only Coverage Curve (first 30 steps) ────────────────────
def fig_kev_coverage_curve(eval_path: Path = DATA / "evaluation.json",
                           out: Path = PLOT_DIR / "kev_coverage_curve.pdf",
                           max_steps: int = 30) -> None:
    """Staircase plot of KEV coverage in first 30 steps.

    Unlike the total-coverage curve (all plans → 100%), this reveals
    the ordering advantage: ILP covers all 5 KEVs by step 4.
    Dependabot does not cover the first KEV until step 18.
    """
    data = json.loads(eval_path.read_text())
    kev_set = set(KEV_IDS)
    n_kev = len(KEV_IDS)

    fig, ax = plt.subplots(figsize=(7, 4))

    for plan in data["plans"]:
        pname = plan["name"]
        if pname not in PLAN_ORDER:
            continue
        kev_covered = set()
        xs = [0]
        ys = [0]
        for step in plan["steps"][:max_steps]:
            for cov in step["covers"]:
                if cov in kev_set:
                    kev_covered.add(cov)
            xs.append(step["rank"])
            ys.append(len(kev_covered))
        ax.step(xs, ys, where="post",
                label=LABELS[pname],
                color=COLORS[pname],
                linewidth=2,
                linestyle="--" if "baseline" in pname else "-")

    # Reference line for full KEV coverage
    ax.axhline(n_kev, color="#cccccc", linestyle=":", linewidth=1, zorder=0)
    ax.text(max_steps - 0.5, n_kev + 0.05, "All 5 KEVs covered",
            ha="right", va="bottom", fontsize=8, color="#888888")

    ax.set_xlabel("Number of upgrade actions")
    ax.set_ylabel("KEV vulnerabilities covered")
    ax.set_xlim(0, max_steps)
    ax.set_ylim(-0.1, n_kev + 0.5)
    ax.set_yticks(range(n_kev + 1))
    ax.set_title(
        f"KEV vulnerability coverage in first {max_steps} upgrade actions\n"
        "ILP covers all 5 KEVs by step 4; CVSS/Dependabot stay at 0 until step 18",
        fontsize=10,
    )

    # Annotate ILP step-4 milestone
    ax.annotate("ILP: all 5\ncovered by\nstep 4",
                xy=(4, 5), xytext=(8, 4.3),
                arrowprops=dict(arrowstyle="->", color="#0072B2", lw=1.0),
                fontsize=8, color="#0072B2", ha="center")

    ax.legend(loc="lower right", fontsize=8.5, ncol=2)
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved %s", out)


# ── Figure 4: Cross-Ecosystem Forest Plot ─────────────────────────────────
def fig_cross_ecosystem(out: Path = PLOT_DIR / "cross_ecosystem.pdf") -> None:
    """Forest plot: ILP AUCC vs random 95% CI for npm, Maven, PyPI.

    Each ecosystem row shows ILP as a filled dot above the CI error bar,
    making the consistent advantage immediately legible.
    """
    def _load(results_csv: Path, ci_json: Path, label: str) -> dict:
        df = pd.read_csv(results_csv)
        ci = json.loads(ci_json.read_text())
        ilp_aucc = float(df[df["plan_name"] == "kevgraph_ilp"]["aucc_kev"].iloc[0])
        epss_aucc = float(df[df["plan_name"] == "baseline_epss"]["aucc_kev"].iloc[0])
        return {
            "name": label,
            "ilp_aucc": ilp_aucc,
            "rand_mean": ci["aucc_kev"]["mean"],
            "ci_lo": ci["aucc_kev"]["ci_lo_95"],
            "ci_hi": ci["aucc_kev"]["ci_hi_95"],
            "epss_aucc": epss_aucc,
        }

    ecosystems = [
        _load(DATA / "results.csv", DATA / "random_ci.json",
              "npm\n(924 repos, 5 KEV, 0.48% density)"),
        _load(DATA / "maven/results.csv", DATA / "maven/random_ci.json",
              "Maven\n(1,200 repos, 7 KEV, 2.37% density)"),
        _load(DATA / "pypi/results.csv", DATA / "pypi/random_ci.json",
              "PyPI\n(300 repos, 1 KEV, 0.12% density)"),
    ]

    fig, ax = plt.subplots(figsize=(7, 3.5))

    y_positions = [2, 1, 0]
    eco_colors = ["#0072B2", "#009E73", "#D55E00"]

    for i, (eco, ypos, color) in enumerate(zip(ecosystems, y_positions, eco_colors)):
        # CI bar
        ax.plot([eco["ci_lo"], eco["ci_hi"]], [ypos, ypos],
                color="#999999", linewidth=4, alpha=0.4, solid_capstyle="round")
        # Random mean marker
        ax.scatter([eco["rand_mean"]], [ypos], color="#999999", marker="|",
                   s=150, linewidths=2, zorder=4)
        # EPSS marker
        ax.scatter([eco["epss_aucc"]], [ypos + 0.18], color="#009E73",
                   marker="^", s=60, zorder=5, alpha=0.8)
        # ILP dot (primary result)
        ax.scatter([eco["ilp_aucc"]], [ypos], color=color, s=120, zorder=6,
                   marker="D", label=eco["name"])
        # Annotate ILP value
        ax.text(eco["ilp_aucc"] + 0.008, ypos, f'{eco["ilp_aucc"]:.4f}',
                va="center", fontsize=8.5, fontweight="bold", color=color)
        # Annotate gap
        gap = eco["ilp_aucc"] - eco["ci_hi"]
        ax.text(eco["ci_hi"] + 0.005, ypos - 0.22,
                f'+{gap:.3f} above CI',
                va="top", fontsize=7.5, color=color, style="italic")

    # Legend elements
    legend_elements = [
        mpatches.Patch(color="#0072B2", label="KEVGraph ILP"),
        plt.Line2D([0], [0], color="#999999", linewidth=4, alpha=0.4, label="Random 95% CI"),
        plt.Line2D([0], [0], color="#999999", marker="|", linestyle="None",
                   markersize=10, markeredgewidth=2, label="Random mean"),
        plt.Line2D([0], [0], color="#009E73", marker="^", linestyle="None",
                   markersize=7, label="EPSS-first"),
    ]
    ax.legend(handles=legend_elements, loc="lower left", fontsize=8, framealpha=0.9)

    ax.set_yticks(y_positions)
    ax.set_yticklabels([e["name"] for e in ecosystems], fontsize=9)
    ax.set_xlabel(r"AUCC$_{\mathrm{KEV}}$ (higher = better)")
    ax.set_xlim(0.1, 1.12)
    ax.set_ylim(-0.5, 2.7)
    ax.set_title(
        "Cross-ecosystem KEV prioritisation advantage\n"
        "ILP (◆) exceeds random 95% CI in all three ecosystems",
        fontsize=10,
    )

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved %s", out)


# ── Figure 5: Action Efficiency ───────────────────────────────────────────
def fig_action_efficiency(results_path: Path = DATA / "results.csv",
                          ci_path: Path = DATA / "random_ci.json",
                          out: Path = PLOT_DIR / "action_efficiency.pdf") -> None:
    """Bar chart of total upgrade actions with random CI annotation.

    Shows that ILP achieves 15.9% fewer actions than random mean.
    """
    df = pd.read_csv(results_path)
    ci = json.loads(ci_path.read_text())
    rand_mean = ci["n_actions"]["mean"]
    rand_lo = ci["n_actions"]["ci_lo_95"]
    rand_hi = ci["n_actions"]["ci_hi_95"]

    df = df[df["plan_name"].isin(PLAN_ORDER)].copy()
    df["sort_key"] = df["plan_name"].map({p: i for i, p in enumerate(PLAN_ORDER)})
    df = df.sort_values("sort_key", ascending=False)  # bottom-up

    fig, ax = plt.subplots(figsize=(6.5, 3.5))

    y_positions = range(len(df))
    for i, (_, row) in enumerate(df.iterrows()):
        pname = row["plan_name"]
        n_act = row["n_actions"]
        color = COLORS.get(pname, "#333333")
        alpha = 0.85

        if pname == "baseline_random":
            # Show CI for random
            ax.barh(i, rand_mean, color=color, alpha=alpha, height=0.55)
            ax.errorbar(rand_mean, i,
                        xerr=[[rand_mean - rand_lo], [rand_hi - rand_mean]],
                        fmt="none", color="#555555", capsize=5, linewidth=2)
            ax.text(rand_mean + 3, i, f"{rand_mean:.1f} (mean, CI [{rand_lo:.0f}–{rand_hi:.0f}])",
                    va="center", fontsize=7.5, color=color)
        else:
            ax.barh(i, n_act, color=color, alpha=alpha, height=0.55)
            ax.text(n_act + 3, i, f"{int(n_act)}", va="center", fontsize=8.5,
                    color=color, fontweight="bold")

    # Reference line at ILP optimum
    ilp_val = df[df["plan_name"] == "kevgraph_ilp"]["n_actions"].values[0]
    ax.axvline(ilp_val, color="#0072B2", linestyle=":", linewidth=1.5, alpha=0.7)
    ax.text(ilp_val + 1, len(df) - 0.3, f"ILP optimum ({int(ilp_val)})",
            fontsize=8, color="#0072B2")

    ax.set_yticks(list(y_positions))
    ax.set_yticklabels([LABELS[p] for p in df["plan_name"]], fontsize=9)
    ax.set_xlabel("Total upgrade actions to cover all vulnerabilities")
    ax.set_xlim(0, rand_hi + 60)
    ax.set_title(
        "Remediation plan cardinality (fewer = more efficient)\n"
        f"ILP achieves provably optimal {int(ilp_val)} actions (15.9% fewer than random mean)",
        fontsize=10,
    )

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved %s", out)


# ── Figure 6: Scalability (improved) ──────────────────────────────────────
def fig_scalability(scale_path: Path = DATA / "scalability.csv",
                    out: Path = PLOT_DIR / "scalability.pdf") -> None:
    """ILP vs greedy solve time vs corpus size with log y-axis.

    Demonstrates practical viability: ILP <130ms at full scale.
    """
    df = pd.read_csv(scale_path)

    fig, ax = plt.subplots(figsize=(6, 3.5))

    ax.plot(df["size"], df["ilp_time_s"] * 1000, "D-",
            color=COLORS["kevgraph_ilp"], linewidth=2, markersize=7,
            label="KEVGraph ILP (CBC solver)")
    ax.plot(df["size"], df["greedy_time_s"] * 1000, "s--",
            color=COLORS["kevgraph_greedy"], linewidth=2, markersize=7,
            label="KEVGraph Greedy")

    # 200ms practical budget reference
    ax.axhline(200, color="#D55E00", linestyle=":", linewidth=1.5, alpha=0.8)
    ax.text(df["size"].max() * 0.98, 220, "200 ms budget",
            ha="right", fontsize=8, color="#D55E00")

    # Annotate ILP max
    ilp_max_ms = df["ilp_time_s"].max() * 1000
    ax.annotate(f"ILP max: {ilp_max_ms:.0f} ms",
                xy=(df["size"].max(), ilp_max_ms),
                xytext=(df["size"].max() * 0.65, ilp_max_ms * 3),
                arrowprops=dict(arrowstyle="->", color=COLORS["kevgraph_ilp"], lw=1.2),
                fontsize=8, color=COLORS["kevgraph_ilp"])

    ax.set_yscale("log")
    ax.set_xlabel("Number of repositories in corpus")
    ax.set_ylabel("Solve time (ms, log scale)")
    ax.set_title(
        "Planning runtime vs corpus size (npm)\n"
        "ILP stays under 130 ms across all sizes; 2,741 candidate fixes",
        fontsize=10,
    )
    ax.legend(fontsize=9)
    ax.set_xticks(df["size"])
    ax.set_xticklabels([str(s) for s in df["size"]])

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved %s", out)


# ── Orchestrator ───────────────────────────────────────────────────────────
def generate_all(eval_path: Path = DATA / "evaluation.json") -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    log.info("Generating redesigned KEVGraph figures...")
    fig_kev_heatmap(eval_path)
    fig_aucc_comparison()
    fig_kev_coverage_curve(eval_path)
    fig_cross_ecosystem()
    fig_action_efficiency()
    fig_scalability()
    log.info("All 6 figures written to %s", PLOT_DIR)


if __name__ == "__main__":
    generate_all()

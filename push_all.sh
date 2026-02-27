#!/usr/bin/env bash
# push_all.sh — initialise, commit, and push the KEVGraph scaffold.
# Idempotent: safe to re-run. Never writes tokens to tracked files.
set -euo pipefail

# ── Colour helpers ───────────────────────────────────────────────────────────
red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
info()  { printf '\033[1;34m>> %s\033[0m\n' "$*"; }

# ── Work from the repo root ─────────────────────────────────────────────────
cd "$(dirname "$0")"

# ── Initialise git if needed ─────────────────────────────────────────────────
if [ ! -d .git ]; then
    info "No .git found — initialising repository"
    git init -b main
fi

# ── Safety: verify branch is main ────────────────────────────────────────────
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    red "ABORT: Current branch is '$BRANCH', expected 'main'."
    exit 1
fi

# ── Safety: verify remote 'origin' exists ────────────────────────────────────
if ! git remote get-url origin >/dev/null 2>&1; then
    red "ABORT: No remote called 'origin'."
    red "Add one with:  git remote add origin <your-repo-url>"
    exit 1
fi

# ── 1. Show current status ──────────────────────────────────────────────────
info "git status"
git status

# ── 2. Write .gitignore ─────────────────────────────────────────────────────
info "Writing .gitignore"
cat > .gitignore << 'GITIGNORE'
# ── Python ───────────────────────────────────────────────────────────────────
__pycache__/
*.py[cod]
*.pyo
*.egg-info/
*.egg
dist/
build/
.venv/
venv/
env/

# ── Test / lint caches ───────────────────────────────────────────────────────
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/

# ── OS junk ──────────────────────────────────────────────────────────────────
.DS_Store
Thumbs.db

# ── Secrets (NEVER commit tokens) ───────────────────────────────────────────
.env
.env.*
!.env.example

# ── Pipeline data / large artifacts ──────────────────────────────────────────
data/cached_api/
data/lockfiles/
data/graphs/
data/raw/
cache/
*.tar.gz
*.zip
*.pkl
*.parquet
GITIGNORE

# ── 3. Write README.md ──────────────────────────────────────────────────────
info "Writing README.md"
cat > README.md << 'README'
# KEVGraph

Reproducible pipeline for the **KEVGraph** paper: prioritised dependency
remediation using CISA KEV and OSV vulnerability data.

## Data Sources (all public)

| Source | Purpose | Endpoint |
|--------|---------|----------|
| GitHub Code Search | Find repos with `package-lock.json` | `api.github.com/search/code` |
| OSV | Vulnerability data for npm packages | `api.osv.dev/v1/querybatch` |
| CISA KEV | Known Exploited Vulnerabilities catalogue | CISA JSON feed |
| deps.dev | Package metadata and advisories | `api.deps.dev/v3alpha` |
| npm registry | Package versions and dist-tags | `registry.npmjs.org` |
| FIRST EPSS | Exploit Prediction Scoring System | `api.first.org/data/v1/epss` |

## Setup

```bash
# 1. Clone
git clone <this-repo-url>
cd kevgraph

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install
pip install -e ".[dev]"

# 4. Provide a GitHub token (classic PAT, public_repo scope)
export GITHUB_TOKEN="ghp_..."    # do NOT commit this
```

## Run

```bash
# Full pipeline (all 8 stages)
python -m src.pipeline

# Resume from the last completed stage
python -m src.pipeline --resume

# Run a single stage
python -m src.pipeline --stage collect

# Or use Make targets
make collect      # Stage 1: discover 5 000 repos
make fetch        # Stage 2: download lockfiles
make parse        # Stage 3: parse lockfiles -> graphs
make join         # Stage 4: OSV + KEV vulnerability join
make fixes        # Stage 5: candidate-fix generation
make plan         # Stage 6: KEVGraph planners + baselines
make evaluate     # Stage 7: compute metrics
make plot         # Stage 8: generate figures
```

### Docker

```bash
docker build -t kevgraph .
docker run --rm \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -v "$(pwd)/data:/app/data" \
  kevgraph
```

## Pipeline

```
collect_repos -> fetch_lockfiles -> parse_lockfile -> osv_kev_join
                                                           |
                                                     candidate_fixes
                                                           |
                                   +-----------------------+
                                   |                       |
                             planner_greedy           planner_ilp
                                   |                       |
                                   +----------+------------+
                                              |
                                    baselines (x4) + metrics
                                              |
                                           plotting
```

## Planners

| Planner | Algorithm | Guarantees |
|---------|-----------|------------|
| KEVGraph Greedy | Weighted set-cover, KEV-aware tie-breaking | O(ln n) approx |
| KEVGraph ILP | Minimum set-cover via CBC | Optimal (exact) |

## Baselines

| Baseline | Strategy |
|----------|----------|
| Random | Uniform random permutation (seed=42) |
| CVSS-first | Descending max CVSS v3 score |
| EPSS-first | Descending max EPSS probability |
| Dependabot | Severity bucket then alphabetical |

## Metrics

| Metric | Definition |
|--------|------------|
| T_0 | Fraction of vulns with KEV status at time zero |
| T_1 | Fraction of vulns fixed after 1st action |
| T_5 | Fraction of vulns fixed after first 5 actions |
| RT_disc | Reduction in time-to-discovery (days) |
| #actions | Total upgrade actions in the plan |
| cert_size | Edges in the remediation certificate |
| verify_time | Seconds to verify plan coverage |

## Outputs

```
data/
├── manifest.csv           # Repo metadata
├── cached_api/            # Disk-cached API responses
├── lockfiles/             # Raw package-lock.json files
├── graphs/                # GraphML dependency graphs
├── vulns.json             # Merged vulnerability records
├── fixes.json             # Candidate-fix actions
├── evaluation.json        # Plans + metrics
├── results.csv            # Metrics comparison table
└── plots/
    ├── coverage_curve.pdf
    ├── metric_bars.pdf
    ├── kev_impact.pdf
    └── action_distribution.pdf
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | *(required)* | GitHub PAT for code search |
| `KEVGRAPH_N_REPOS` | 5000 | Number of repos to collect |

## Tests

```bash
python -m pytest tests/ -v
```

## License

MIT
README

# ── 4. Stage everything ─────────────────────────────────────────────────────
info "git add -A"
git add -A

# ── 5. Commit (only if there are staged changes) ────────────────────────────
if git diff --cached --quiet; then
    green "Nothing to commit — working tree clean."
else
    info "Committing..."
    git commit -m "KEVGraph pipeline scaffold"
    green "Committed."
fi

# ── 6. Push to origin main ──────────────────────────────────────────────────
info "Pushing to origin main..."
git push -u origin main
green "Done — pushed to origin main."

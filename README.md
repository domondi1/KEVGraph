# KEVGraph

Reproducible pipeline for the **KEVGraph** paper: prioritised dependency remediation using CISA KEV and OSV vulnerability data.

## Data Sources (all public)

| Source | Purpose | Endpoint |
|--------|---------|----------|
| GitHub Code Search | Find repos with `package-lock.json` | `api.github.com/search/code` |
| OSV | Vulnerability data for npm packages | `api.osv.dev/v1/querybatch` |
| CISA KEV | Known Exploited Vulnerabilities catalogue | `cisa.gov/.../known_exploited_vulnerabilities.json` |
| deps.dev | Package metadata and advisories | `api.deps.dev/v3alpha` |
| npm registry | Package versions and dist-tags | `registry.npmjs.org` |
| FIRST EPSS | Exploit Prediction Scoring System | `api.first.org/data/v1/epss` |

## Quick Start

### Prerequisites

- Python 3.11+
- A GitHub personal access token (classic) with `public_repo` scope

### Local

```bash
export GITHUB_TOKEN="ghp_..."

# Install
pip install -e ".[dev]"

# Run full pipeline (8 stages)
python -m src.pipeline

# Or stage-by-stage
make collect    # Stage 1: discover 5000 repos
make fetch      # Stage 2: download lockfiles
make parse      # Stage 3: parse lockfiles -> graphs
make join       # Stage 4: OSV + KEV vulnerability join
make fixes      # Stage 5: candidate-fix generation
make plan       # Stage 6: KEVGraph planners + baselines
make evaluate   # Stage 7: compute metrics
make plot       # Stage 8: generate figures

# Resume from last completed stage
python -m src.pipeline --resume
```

### Docker

```bash
docker build -t kevgraph .
docker run --rm \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -v "$(pwd)/data:/app/data" \
  kevgraph
```

## Pipeline Stages

```
collect_repos ──> fetch_lockfiles ──> parse_lockfile ──> osv_kev_join
                                                              │
                                                        candidate_fixes
                                                              │
                                    ┌─────────────────────────┤
                                    │                         │
                              planner_greedy             planner_ilp
                                    │                         │
                                    └──────────┬──────────────┘
                                               │
                                     baselines (x4) + metrics
                                               │
                                            plotting
```

## Planners

| Planner | Algorithm | Guarantees |
|---------|-----------|------------|
| **KEVGraph Greedy** | Weighted set-cover with KEV-aware tie-breaking (KEV count > CVSS > EPSS) | O(ln n) approximation |
| **KEVGraph ILP** | Minimum set-cover via CBC integer programming | Optimal (exact) |

## Baselines

| Baseline | Ordering Strategy |
|----------|-------------------|
| Random | Uniform random permutation (seed=42) |
| CVSS-first | Descending max CVSS v3 score |
| EPSS-first | Descending max EPSS probability |
| Dependabot | Severity bucket (critical > high > medium > low), then alphabetical |

## Metrics

| Metric | Definition |
|--------|------------|
| T_0 | Fraction of vulns with KEV status at time zero |
| T_1 | Fraction of vulns fixed after first action |
| T_5 | Fraction of vulns fixed after first 5 actions |
| RT_disc | Reduction in time-to-discovery (KEV due_date - date_added, days) |
| #actions | Total upgrade actions in the plan |
| cert_size | Edges in the remediation certificate |
| verify_time | Wall-clock seconds to verify plan coverage |

## Outputs

```
data/
├── manifest.csv          # Repo metadata (5000 rows)
├── cached_api/           # Disk-cached API responses (SHA-256 keyed)
├── lockfiles/            # Raw package-lock.json files
├── graphs/               # NetworkX GraphML dependency graphs
├── vulns.json            # Merged OSV + KEV vulnerability records
├── fixes.json            # Candidate-fix actions
├── evaluation.json       # Plans + metrics (machine-readable)
├── results.csv           # Metrics comparison table
└── plots/
    ├── coverage_curve.pdf
    ├── metric_bars.pdf
    ├── kev_impact.pdf
    └── action_distribution.pdf
```

## Caching and Rate Limits

- All API responses are cached to `data/cached_api/` with a 72-hour TTL
- Per-domain token-bucket rate limiting (GitHub 8 req/s, npm 15 req/s, etc.)
- Automatic retry with exponential backoff on 429 and 5xx responses
- GitHub rate-limit headers (`X-RateLimit-Reset`) are respected
- Re-running the pipeline skips already-fetched data

## Configuration

Override defaults via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | (required) | GitHub PAT for code search |
| `KEVGRAPH_N_REPOS` | 5000 | Number of repos to collect |

## License

MIT

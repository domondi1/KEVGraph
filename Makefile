.PHONY: install run collect fetch parse join fixes plan evaluate plot all clean docker test lint mre snapshot scan-mre scan-full

PYTHON ?= python3
TODAY  := $(shell date -u +%Y-%m-%d)

install:
	$(PYTHON) -m pip install -e ".[dev]"

# ── Quality gates ─────────────────────────────────────────────────────────────
test:
	pytest tests/ -v

lint:
	ruff check src/ tests/

# ── Minimal reproducible example (5 curated repos, no search API needed) ─────
mre:
	$(PYTHON) -m src.collect_repos --curated data/curated_repos.txt
	$(PYTHON) -m src.fetch_lockfiles
	$(PYTHON) -m src.parse_lockfile
	$(PYTHON) -m src.osv_kev_join
	$(PYTHON) -m src.candidate_fixes

# ── KEV-positive discovery ────────────────────────────────────────────────────
# MRE: 20 positive repos, curated seed, no GitHub search needed
scan-mre:
	$(PYTHON) -m src.find_kev_positive \
		--seed-file data/curated_repos.txt \
		--max-candidates 500 \
		--target-n 20 \
		--target-control 20 \
		--random-seed 42

# Paper: 100 positive repos from bounded GitHub search (cap 5 000 candidates)
scan-full:
	$(PYTHON) -m src.find_kev_positive \
		--max-candidates 5000 \
		--target-n 100 \
		--target-control 100 \
		--random-seed 42

# ── Reproducibility snapshot ─────────────────────────────────────────────────
snapshot:
	$(PYTHON) scripts/consolidate_snapshot.py --tag $(TODAY)

# ── Individual pipeline stages ───────────────────────────────────────────────
collect:
	$(PYTHON) -m src.collect_repos

fetch:
	$(PYTHON) -m src.fetch_lockfiles

parse:
	$(PYTHON) -m src.parse_lockfile

join:
	$(PYTHON) -m src.osv_kev_join

fixes:
	$(PYTHON) -m src.candidate_fixes

plan:
	$(PYTHON) -m src.pipeline --stage plan

evaluate:
	$(PYTHON) -m src.pipeline --stage evaluate

plot:
	$(PYTHON) -m src.plotting

# ── Full pipeline ────────────────────────────────────────────────────────────
all:
	$(PYTHON) -m src.pipeline

# ── Docker ───────────────────────────────────────────────────────────────────
docker:
	docker build -t kevgraph .
	docker run --rm -e GITHUB_TOKEN="$$GITHUB_TOKEN" -v "$$(pwd)/data:/app/data" kevgraph

clean:
	rm -rf data/cached_api data/lockfiles data/graphs data/plots data/manifest.csv data/results.csv

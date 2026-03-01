.PHONY: install run collect fetch parse join fixes plan evaluate plot all clean docker test lint mre snapshot

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

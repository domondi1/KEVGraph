"""Stage 4: Join dependency graphs with OSV + CISA KEV vulnerability data.

Workflow:
  1. Fetch the CISA KEV catalogue (JSON feed) → set of CVE IDs with
     metadata (date added, due date, vendor, product).
  2. For each unique (package, version) across all parsed graphs, query the
     OSV API to obtain matching vulnerabilities.
  3. Enrich OSV records with KEV membership, CVSS scores, and EPSS scores.
  4. Persist a merged vuln table to  data/vulns.json  and annotate graph
     nodes with vulnerability IDs.

Usage:
    python -m src.osv_kev_join
"""

from __future__ import annotations

import csv as _csv
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
from tqdm import tqdm

from . import config
from .rate_limit import get_json, post_json

log = logging.getLogger(__name__)

VULNS_PATH = config.DATA_DIR / "vulns.json"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class VulnRecord:
    vuln_id: str                        # e.g. "GHSA-..." or "CVE-..."
    aliases: list[str] = field(default_factory=list)
    package: str = ""
    ecosystem: str = "npm"
    affected_range: str = ""
    fixed_version: str | None = None    # earliest fix from OSV
    severity_type: str = ""             # CVSS_V3, etc.
    severity_score: float = 0.0
    epss_score: float = 0.0
    in_kev: bool = False
    kev_date_added: str = ""
    kev_due_date: str = ""
    summary: str = ""


# ── KEV catalogue ────────────────────────────────────────────────────────────

def fetch_kev_catalogue() -> dict[str, dict]:
    """Return {cve_id: kev_entry} from the CISA KEV JSON feed or a local snapshot.

    When KEVGRAPH_KEV_SNAPSHOT is set, the catalogue is loaded from that file
    instead of making a live network request.  This guarantees that the exact
    same KEV data used to produce the paper results is used during reproduction.
    """
    if config.KEV_SNAPSHOT_PATH:
        log.info("Loading KEV from snapshot: %s", config.KEV_SNAPSHOT_PATH)
        raw = json.loads(config.KEV_SNAPSHOT_PATH.read_text())
        catalogue = {
            entry.get("cveID", ""): entry
            for entry in raw.get("vulnerabilities", [])
            if entry.get("cveID")
        }
        log.info("KEV snapshot loaded: %d entries", len(catalogue))
        return catalogue

    data = get_json(config.CISA_KEV_URL)
    catalogue: dict[str, dict] = {}
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cveID", "")
        if cve:
            catalogue[cve] = entry
    log.info("KEV catalogue: %d entries", len(catalogue))
    return catalogue


# ── OSV queries ──────────────────────────────────────────────────────────────

def _query_osv_batch(queries: list[dict]) -> list[list[dict]]:
    """POST to /v1/querybatch. Returns list-of-lists of vulns."""
    url = f"{config.OSV_API}/querybatch"
    body = {"queries": queries}
    resp = post_json(url, body)
    return [r.get("vulns", []) for r in resp.get("results", [])]


def query_osv_for_packages(
    pkg_versions: list[tuple[str, str]],
) -> dict[tuple[str, str], list[dict]]:
    """Query OSV for a list of (name, version) tuples. Returns raw vuln dicts."""
    results: dict[tuple[str, str], list[dict]] = {}

    # Build batches of up to OSV_BATCH_SIZE
    queries = []
    keys = []
    for name, version in pkg_versions:
        queries.append(
            {"package": {"name": name, "ecosystem": "npm"}, "version": version}
        )
        keys.append((name, version))

    for start in tqdm(
        range(0, len(queries), config.OSV_BATCH_SIZE),
        desc="OSV batch queries",
        unit="batch",
    ):
        batch_q = queries[start : start + config.OSV_BATCH_SIZE]
        batch_k = keys[start : start + config.OSV_BATCH_SIZE]
        try:
            batch_results = _query_osv_batch(batch_q)
        except Exception as exc:
            log.warning("OSV batch failed at offset %d: %s", start, exc)
            batch_results = [[] for _ in batch_q]
        for key, vulns in zip(batch_k, batch_results):
            results[key] = vulns

    return results


# ── EPSS enrichment (FIRST.org public API) ───────────────────────────────────

def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs. Returns {cve: score}."""
    scores: dict[str, float] = {}
    # FIRST EPSS API accepts comma-separated CVE list, max ~100 at a time
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i : i + 100]
        csv_ids = ",".join(batch)
        url = f"https://api.first.org/data/v1/epss?cve={csv_ids}"
        try:
            data = get_json(url)
            for entry in data.get("data", []):
                scores[entry["cve"]] = float(entry.get("epss", 0))
        except Exception as exc:
            log.warning("EPSS fetch failed: %s", exc)
    return scores


# ── Build unified vuln records ───────────────────────────────────────────────

def _extract_severity(vuln: dict) -> tuple[str, float]:
    """Extract best CVSS score from an OSV record."""
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            # score might be the vector string; try to extract base score
            if isinstance(score_str, (int, float)):
                return "CVSS_V3", float(score_str)
            # For vector strings, use the database_specific if available
    # Fallback: check database_specific
    db = vuln.get("database_specific", {})
    cvss = db.get("cvss", db.get("severity", ""))
    if isinstance(cvss, (int, float)):
        return "CVSS_V3", float(cvss)
    return "", 0.0


def _extract_fixed_version(vuln: dict, pkg_name: str) -> str | None:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") == pkg_name and pkg.get("ecosystem") == "npm":
            for rng in affected.get("ranges", []):
                for evt in rng.get("events", []):
                    if "fixed" in evt:
                        return evt["fixed"]
    return None


def build_vuln_records(
    osv_results: dict[tuple[str, str], list[dict]],
    kev_catalogue: dict[str, dict],
) -> dict[str, VulnRecord]:
    """Merge OSV results with KEV catalogue. Returns {vuln_id: VulnRecord}."""
    records: dict[str, VulnRecord] = {}
    all_cve_ids: set[str] = set()

    for (pkg_name, pkg_version), vulns in osv_results.items():
        for v in vulns:
            vid = v.get("id", "")
            if vid in records:
                continue
            aliases = v.get("aliases", [])

            # Build the full CVE candidate set:
            #   • CVEs found in the aliases list (common for GHSA-primary records)
            #   • The vuln_id itself when it is a CVE (NVD-primary records, rare for npm)
            # Both paths must be checked so we don't silently miss KEV matches.
            cves: list[str] = [a for a in aliases if a.startswith("CVE-")]
            if vid.startswith("CVE-") and vid not in cves:
                cves.insert(0, vid)
            all_cve_ids.update(cves)

            sev_type, sev_score = _extract_severity(v)
            fixed = _extract_fixed_version(v, pkg_name)

            in_kev = any(cve in kev_catalogue for cve in cves)
            kev_entry = next(
                (kev_catalogue[cve] for cve in cves if cve in kev_catalogue), {}
            )

            records[vid] = VulnRecord(
                vuln_id=vid,
                aliases=aliases,
                package=pkg_name,
                affected_range=str(
                    v.get("affected", [{}])[0]
                    .get("ranges", [{}])[0]
                    .get("events", [])
                )
                if v.get("affected")
                else "",
                fixed_version=fixed,
                severity_type=sev_type,
                severity_score=sev_score,
                in_kev=in_kev,
                kev_date_added=kev_entry.get("dateAdded", ""),
                kev_due_date=kev_entry.get("dueDate", ""),
                summary=v.get("summary", "")[:200],
            )

    # ── Enrich with EPSS ─────────────────────────────────────────────────
    cve_list = sorted(all_cve_ids)
    if cve_list:
        epss = _fetch_epss(cve_list)
        for rec in records.values():
            cve_ids_for_rec = [rec.vuln_id] + rec.aliases
            for cid in cve_ids_for_rec:
                if cid in epss:
                    rec.epss_score = max(rec.epss_score, epss[cid])

    # ── Diagnostic counters ───────────────────────────────────────────────
    n_total = len(records)
    n_with_cve = sum(
        1 for r in records.values()
        if r.vuln_id.startswith("CVE-") or any(a.startswith("CVE-") for a in r.aliases)
    )
    n_kev = sum(1 for r in records.values() if r.in_kev)
    log.info(
        "KEV join stats: total_vulns=%d  vulns_with_cve_alias=%d  matched_kev_by_alias=%d",
        n_total, n_with_cve, n_kev,
    )
    return records


# ── Annotate graphs ──────────────────────────────────────────────────────────

def annotate_graphs(records: dict[str, VulnRecord]) -> None:
    """Re-read each GraphML, stamp vuln IDs onto nodes, re-write."""
    # Build lookup: (pkg, version) -> list of vuln_ids
    pkg_vulns: dict[tuple[str, str], list[str]] = {}
    for rec in records.values():
        key = (rec.package, "")  # we'll match on package name + affected check below
        pkg_vulns.setdefault(key, []).append(rec.vuln_id)

    graph_files = sorted(config.GRAPH_DIR.glob("*.graphml"))
    for gf in tqdm(graph_files, desc="Annotating graphs", unit="graph"):
        G = nx.read_graphml(str(gf))
        changed = False
        for node, attrs in G.nodes(data=True):
            name = attrs.get("name", "")
            # Check if this package has any vuln
            vulns_for_pkg = [
                r.vuln_id
                for r in records.values()
                if r.package == name
            ]
            if vulns_for_pkg:
                G.nodes[node]["vulns"] = ",".join(vulns_for_pkg)
                changed = True
        if changed:
            nx.write_graphml(G, str(gf))


# ── Persistence ──────────────────────────────────────────────────────────────

def save_vulns(records: dict[str, VulnRecord]) -> None:
    data = {vid: asdict(rec) for vid, rec in records.items()}
    VULNS_PATH.write_text(json.dumps(data, indent=2))
    log.info("Wrote %s", VULNS_PATH)


def load_vulns() -> dict[str, VulnRecord]:
    data = json.loads(VULNS_PATH.read_text())
    return {
        vid: VulnRecord(**{k: v for k, v in d.items()})
        for vid, d in data.items()
    }


# ── KEV density per repo ─────────────────────────────────────────────────────

def write_kev_density(records: dict[str, VulnRecord]) -> None:
    """Compute per-repo KEV density, write kev_density.csv, warn on KEV=0,
    and append corpus-summary rows to results.csv.

    Reads the annotated GraphML files to map vulns back to source repos.
    """
    graph_files = sorted(config.GRAPH_DIR.glob("*.graphml"))
    if not graph_files:
        log.warning("No graph files found; skipping kev_density output.")
        return

    density_rows: list[dict] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for gf in graph_files:
        G = nx.read_graphml(str(gf))
        source = G.graph.get("source", gf.stem)
        repo_full_name = source.replace("__", "/", 1)

        # All package names present in this repo's graph
        pkg_names = {attrs.get("name", "") for _, attrs in G.nodes(data=True)}
        pkg_names.discard("")

        # Total distinct (name, version) pairs (≈ lockfile entries)
        total_pkgs = sum(
            1 for _, a in G.nodes(data=True) if a.get("name") and a.get("version")
        )

        # Vulns whose package is present in this repo
        repo_vulns = [r for r in records.values() if r.package in pkg_names]
        unique_vuln_ids = {r.vuln_id for r in repo_vulns}
        total_vulns = len(unique_vuln_ids)
        kev_count = sum(1 for r in repo_vulns if r.in_kev)
        kev_rate = kev_count / total_vulns if total_vulns > 0 else 0.0

        if kev_count == 0:
            log.warning(
                "repo %s has kev_count=0 (total_vulns=%d, total_pkgs=%d)",
                repo_full_name, total_vulns, total_pkgs,
            )

        density_rows.append({
            "repo_full_name": repo_full_name,
            "total_pkgs": total_pkgs,
            "total_vulns": total_vulns,
            "kev_count": kev_count,
            "kev_rate": round(kev_rate, 6),
            "scan_at": now_iso,
        })

    # ── Write authoritative per-repo file ────────────────────────────────
    density_path = config.KEV_SCAN_DIR / "kev_density.csv"
    density_fields = ["repo_full_name", "total_pkgs", "total_vulns", "kev_count", "kev_rate", "scan_at"]
    with open(density_path, "w", newline="") as fh:
        writer = _csv.DictWriter(fh, fieldnames=density_fields)
        writer.writeheader()
        writer.writerows(density_rows)
    log.info("Wrote %s (%d repos)", density_path, len(density_rows))

    # ── Append corpus-summary rows to results.csv ─────────────────────────
    kev_positive = sum(1 for r in density_rows if r["kev_count"] > 0)
    kev_zero = len(density_rows) - kev_positive
    results_fields = ["plan_name", "T0", "T1", "T5", "RTdisc_days", "n_actions", "cert_size", "verify_time_s"]
    write_header = not config.RESULTS_CSV.exists()
    with open(config.RESULTS_CSV, "a", newline="") as fh:
        writer = _csv.DictWriter(fh, fieldnames=results_fields, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerow({
            "plan_name": "kev_summary",
            "T0": "corpus_kev_positive_repos",
            "T1": kev_positive,
            "T5": "-", "RTdisc_days": "-", "n_actions": "-",
            "cert_size": "-", "verify_time_s": "-",
        })
        writer.writerow({
            "plan_name": "kev_summary",
            "T0": "corpus_kev_zero_repos",
            "T1": kev_zero,
            "T5": "-", "RTdisc_days": "-", "n_actions": "-",
            "cert_size": "-", "verify_time_s": "-",
        })
    log.info(
        "Appended kev_summary to %s (positive=%d, zero=%d)",
        config.RESULTS_CSV, kev_positive, kev_zero,
    )


# ── Orchestration ────────────────────────────────────────────────────────────

def run_join() -> dict[str, VulnRecord]:
    """Full Stage 4: query OSV + KEV, build records, annotate graphs."""
    # Collect unique (pkg, version) pairs across all graphs
    pkg_versions: set[tuple[str, str]] = set()
    graph_files = sorted(config.GRAPH_DIR.glob("*.graphml"))
    if not graph_files:
        raise FileNotFoundError("No graphs found – run parse_lockfile first.")

    for gf in tqdm(graph_files, desc="Reading graphs", unit="graph"):
        G = nx.read_graphml(str(gf))
        for _, attrs in G.nodes(data=True):
            name = attrs.get("name", "")
            ver = attrs.get("version", "")
            if name and ver:
                pkg_versions.add((name, ver))

    log.info("Unique (package, version) pairs: %d", len(pkg_versions))

    kev = fetch_kev_catalogue()
    osv_results = query_osv_for_packages(sorted(pkg_versions))
    records = build_vuln_records(osv_results, kev)
    save_vulns(records)
    annotate_graphs(records)
    write_kev_density(records)
    return records


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    run_join()


if __name__ == "__main__":
    main()

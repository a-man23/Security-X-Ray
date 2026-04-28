"""
Collect core paper metrics from Security X-Ray crawl outputs.

Writes normalized CSV/JSON tables to collection/output/ by default.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect core dataset metrics from crawl JSON outputs.")
    p.add_argument("--output-dir", type=Path, default=Path("output"), help="Directory containing crawl JSON files.")
    p.add_argument(
        "--dest",
        type=Path,
        default=Path("collection") / "output",
        help="Directory where metric tables are written.",
    )
    p.add_argument(
        "--candidates",
        type=Path,
        default=Path("data") / "classification_candidates.json",
        help="Path to classification_candidates.json for queue/process metrics.",
    )
    return p.parse_args()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def discover_site_reports(output_dir: Path) -> list[tuple[Path, dict]]:
    reports: list[tuple[Path, dict]] = []
    for path in sorted(output_dir.glob("*.json")):
        try:
            blob = read_json(path)
        except Exception:
            continue
        if isinstance(blob, dict) and "crawl_metadata" in blob and "summary" in blob:
            reports.append((path, blob))
    return reports


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def safe_variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.pvariance(values)


def main() -> int:
    args = parse_args()
    reports = discover_site_reports(args.output_dir)
    if not reports:
        raise SystemExit(f"No per-site crawl reports found in {args.output_dir}")

    args.dest.mkdir(parents=True, exist_ok=True)

    site_rows: list[dict] = []
    site_category_rows: list[dict] = []
    status_rows: list[dict] = []
    site_domain_sets: dict[str, set[str]] = {}
    shared_domain_counts: Counter[str] = Counter()
    provider_counts: Counter[str] = Counter()
    domain_rollup: dict[str, dict] = defaultdict(
        lambda: {
            "domain": "",
            "site_count": 0,
            "sites": set(),
            "max_score": 0,
            "avg_score": 0.0,
            "scores": [],
            "primary_categories": Counter(),
            "providers": Counter(),
        }
    )

    site_scores: list[float] = []
    domain_scores: list[float] = []

    for path, report in reports:
        meta = report.get("crawl_metadata", {})
        summary = report.get("summary", {})
        pages = report.get("pages", [])
        site = str(meta.get("site_domain", path.stem))

        risk = summary.get("risk_score", {}) if isinstance(summary.get("risk_score"), dict) else {}
        site_score = float(risk.get("score", 0))
        site_scores.append(site_score)

        pages_status = Counter(p.get("status", "unknown") for p in pages if isinstance(p, dict))
        site_rows.append(
            {
                "site_domain": site,
                "target_url": meta.get("target_url", ""),
                "pages_crawled": int(meta.get("pages_crawled", 0)),
                "pages_blocked_by_robots": int(meta.get("pages_blocked_by_robots", 0)),
                "third_party_count": int(summary.get("third_party_count", 0)),
                "third_party_script_count": int(summary.get("third_party_script_count", 0)),
                "unique_third_party_domains": int(summary.get("unique_third_party_domains", 0)),
                "risk_score": int(risk.get("score", 0)),
                "risk_tier": risk.get("tier", "low"),
                "risk_exposure_score": int(risk.get("exposure_score", 0)),
                "risk_threat_score": int(risk.get("threat_score", 0)),
                "risk_confidence_score": int(risk.get("confidence_score", 0)),
                "status_ok": pages_status.get("ok", 0),
                "status_blocked_by_robots": pages_status.get("blocked_by_robots", 0),
                "status_timeout": pages_status.get("timeout", 0),
                "status_connection_error": pages_status.get("connection_error", 0),
                "status_error": pages_status.get("error", 0),
                "status_non_html": pages_status.get("non_html", 0),
            }
        )

        for status, count in sorted(pages_status.items()):
            status_rows.append({"site_domain": site, "status": status, "count": int(count)})

        by_category = summary.get("by_category", {}) if isinstance(summary.get("by_category"), dict) else {}
        for cat, count in sorted(by_category.items()):
            site_category_rows.append(
                {"site_domain": site, "category": cat, "count": int(count)}
            )

        by_provider = summary.get("by_provider", {}) if isinstance(summary.get("by_provider"), dict) else {}
        provider_counts.update({k: int(v) for k, v in by_provider.items()})

        domains = set(summary.get("third_party_domains", []) or [])
        site_domain_sets[site] = domains
        shared_domain_counts.update(domains)

        for row in summary.get("domain_risk_scores", []) or []:
            if not isinstance(row, dict):
                continue
            domain = row.get("domain")
            if not domain:
                continue
            d = domain_rollup[domain]
            d["domain"] = domain
            score = float(row.get("score", 0))
            d["scores"].append(score)
            d["max_score"] = max(d["max_score"], score)
            d["sites"].add(site)
            if row.get("primary_category"):
                d["primary_categories"][str(row["primary_category"])] += 1
            if row.get("provider"):
                d["providers"][str(row["provider"])] += 1
            domain_scores.append(score)

    # Overlap matrix (shared third-party domains by site pair)
    sites = sorted(site_domain_sets.keys())
    overlap_rows: list[dict] = []
    for s1 in sites:
        row = {"site_domain": s1}
        d1 = site_domain_sets[s1]
        for s2 in sites:
            d2 = site_domain_sets[s2]
            row[s2] = len(d1.intersection(d2))
        overlap_rows.append(row)

    shared_rows = [
        {"domain": d, "site_count": c}
        for d, c in shared_domain_counts.most_common()
        if c > 1
    ]
    provider_rows = [
        {"provider": p, "resource_count": c}
        for p, c in provider_counts.most_common()
    ]

    domain_rollup_rows: list[dict] = []
    for domain, data in domain_rollup.items():
        scores = data.pop("scores")
        data["site_count"] = len(data["sites"])
        data["sites"] = ";".join(sorted(data["sites"]))
        data["avg_score"] = round(sum(scores) / len(scores), 2) if scores else 0.0
        top_cat = data["primary_categories"].most_common(1)
        top_provider = data["providers"].most_common(1)
        data["top_category"] = top_cat[0][0] if top_cat else ""
        data["top_provider"] = top_provider[0][0] if top_provider else ""
        data["max_score"] = int(round(data["max_score"]))
        data.pop("primary_categories")
        data.pop("providers")
        domain_rollup_rows.append(data)

    domain_rollup_rows.sort(key=lambda r: (-r["max_score"], -r["site_count"], r["domain"]))

    # Candidate queue/process metrics
    candidate_metrics = {
        "domains_total": 0,
        "status_counts": {},
    }
    if args.candidates.exists():
        try:
            cand = read_json(args.candidates)
            domains = cand.get("domains", {}) if isinstance(cand, dict) else {}
            candidate_metrics["domains_total"] = len(domains)
            status_counter = Counter()
            for row in domains.values():
                if isinstance(row, dict):
                    status_counter[str(row.get("status", "unknown"))] += 1
            candidate_metrics["status_counts"] = dict(status_counter)
        except Exception:
            pass

    summary_json = {
        "sites_analyzed": len(sites),
        "reports": [str(p) for p, _ in reports],
        "site_risk_distribution": {
            "mean": round(statistics.fmean(site_scores), 2) if site_scores else 0.0,
            "median": round(statistics.median(site_scores), 2) if site_scores else 0.0,
            "max": max(site_scores) if site_scores else 0.0,
            "variance": round(safe_variance(site_scores), 2),
        },
        "domain_risk_distribution": {
            "mean": round(statistics.fmean(domain_scores), 2) if domain_scores else 0.0,
            "median": round(statistics.median(domain_scores), 2) if domain_scores else 0.0,
            "max": max(domain_scores) if domain_scores else 0.0,
            "variance": round(safe_variance(domain_scores), 2),
        },
        "candidate_queue": candidate_metrics,
    }

    write_csv(
        args.dest / "site_metrics.csv",
        site_rows,
        [
            "site_domain",
            "target_url",
            "pages_crawled",
            "pages_blocked_by_robots",
            "third_party_count",
            "third_party_script_count",
            "unique_third_party_domains",
            "risk_score",
            "risk_tier",
            "risk_exposure_score",
            "risk_threat_score",
            "risk_confidence_score",
            "status_ok",
            "status_blocked_by_robots",
            "status_timeout",
            "status_connection_error",
            "status_error",
            "status_non_html",
        ],
    )
    write_csv(args.dest / "site_category_counts.csv", site_category_rows, ["site_domain", "category", "count"])
    write_csv(args.dest / "site_status_counts.csv", status_rows, ["site_domain", "status", "count"])
    write_csv(args.dest / "shared_domains.csv", shared_rows, ["domain", "site_count"])
    write_csv(args.dest / "provider_prevalence.csv", provider_rows, ["provider", "resource_count"])
    write_csv(
        args.dest / "domain_risk_rollup.csv",
        domain_rollup_rows,
        ["domain", "site_count", "sites", "max_score", "avg_score", "top_category", "top_provider"],
    )
    write_csv(args.dest / "site_overlap_matrix.csv", overlap_rows, ["site_domain"] + sites)
    (args.dest / "collection_summary.json").write_text(
        json.dumps(summary_json, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Wrote collection metrics to {args.dest.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

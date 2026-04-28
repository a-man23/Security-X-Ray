""" 
Example Inputs:
  # Single site, default depth 1
  python main.py --url https://example.com
 
  # Multiple sites from a file, depth 2, custom output dir
  python main.py --targets targets.txt --depth 2 --output ./results
 
  # Limit crawl breadth by capping internal links followed per page
  python main.py --targets targets.txt --depth 2 --max-internal-links 25
 
  # Multiple URLs inline
  python main.py --url https://bbc.com --url https://nytimes.com --depth 1
 
  # Combine all site results into one aggregate JSON
  python main.py --targets targets.txt --depth 1 --aggregate

  # Aggregate + graph (writes aggregate_graph.json for offline visualization)
  python main.py --targets targets.txt --aggregate --graph
"""
 
from __future__ import annotations
 
import argparse
import json
import logging
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
 
import requests
 
# Allow running from project root without installing as package
sys.path.insert(0, str(Path(__file__).parent))
 
from crawler import SiteCrawler, RateLimiter, RobotsCache
 
# Logging setup 
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("security_xray")
 
 
# Helpers
 
def safe_filename(url: str) -> str:
    """Convert a URL to a safe filename stem."""
    parsed = urlparse(url)
    name = parsed.netloc + parsed.path
    name = re.sub(r"[^\w\-.]", "_", name).strip("_")
    return name[:120]  # cap length
 
 
def ensure_https(url: str) -> str:
    """Add https:// if scheme is missing."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url
 
 
def load_targets(path: str) -> list[str]:
    """Read one URL per line from a file, skipping blanks and comments."""
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(ensure_https(line))
    return targets
 
 
def write_json(data: dict | list, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info("Wrote %s  (%d bytes)", path, path.stat().st_size)
 
 
def generate_graph_from_input(
    input_path: Path,
    graph_output_path: Path,
    open_browser: bool,
    width: int | None = None,
    height: int | None = None,
) -> bool:
    """Generate graph HTML from a single JSON input (e.g. aggregate_graph.json or one crawl file)."""
    script_path = Path("scripts") / "visualize_graph.py"
    if not script_path.exists():
        logger.warning("Graph script not found: %s", script_path)
        return False

    cmd = [
        sys.executable,
        str(script_path),
        "--input",
        str(input_path),
        "--output",
        str(graph_output_path),
    ]
    if not open_browser:
        cmd.append("--no-open")
    if width is not None:
        cmd.extend(["--width", str(width)])
    if height is not None:
        cmd.extend(["--height", str(height)])

    try:
        subprocess.run(cmd, check=True)
        logger.info("Generated graph HTML: %s", graph_output_path)
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("Graph generation failed (exit %s)", exc.returncode)
        return False


def generate_graph_from_reports(
    report_paths: list[Path],
    graph_output_path: Path,
    open_browser: bool,
    width: int | None = None,
    height: int | None = None,
) -> bool:
    """Generate graph HTML from one or more per-site crawl JSON files (no aggregate_graph.json)."""
    script_path = Path("scripts") / "visualize_graph.py"
    if not script_path.exists():
        logger.warning("Graph script not found: %s", script_path)
        return False

    cmd = [sys.executable, str(script_path), "--output", str(graph_output_path)]
    if len(report_paths) == 1:
        cmd.extend(["--input", str(report_paths[0])])
    else:
        cmd.append("--inputs")
        cmd.extend(str(p) for p in report_paths)
    if not open_browser:
        cmd.append("--no-open")
    if width is not None:
        cmd.extend(["--width", str(width)])
    if height is not None:
        cmd.extend(["--height", str(height)])

    try:
        subprocess.run(cmd, check=True)
        logger.info("Generated graph HTML: %s", graph_output_path)
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("Graph generation failed (exit %s)", exc.returncode)
        return False


def update_unknown_candidates(results: list[dict], path: Path):
    """
    Merge unknown third-party domains into a persistent review file.
    This does not auto-edit classifiers; it builds a safe queue for manual approval.
    """
    existing: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    domains = existing.get("domains", {})
    for result in results:
        site = result.get("crawl_metadata", {}).get("site_domain", "unknown-site")
        for res in result.get("resources", []):
            if res.get("party") != "third-party" or res.get("category") != "unknown":
                continue
            domain = res.get("registrable_domain")
            if not domain:
                continue
            row = domains.setdefault(
                domain,
                {
                    "proposed_category": None,
                    "proposed_provider": None,
                    "seen_count": 0,
                    "sites": [],
                    "example_urls": [],
                    "status": "needs_review",
                },
            )
            row["seen_count"] += 1
            if site not in row["sites"]:
                row["sites"].append(site)
            url = res.get("url")
            if url and url not in row["example_urls"] and len(row["example_urls"]) < 5:
                row["example_urls"].append(url)

    report = {
        "format_version": 1,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "notes": "Review and promote high-confidence entries into data/domain_classifications.json",
        "domains": dict(sorted(domains.items(), key=lambda item: (-item[1].get("seen_count", 0), item[0]))),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    logger.info("Updated unknown domain candidates: %s", path)


def print_summary(result: dict):
    meta = result.get("crawl_metadata", {})
    summ = result.get("summary", {})
    print()
    print("=" * 60)
    print(f"  Site:         {meta.get('site_domain')}")
    print(f"  Target URL:   {meta.get('target_url')}")
    print(f"  Crawled at:   {meta.get('crawled_at')}")
    print(f"  Pages crawled:{meta.get('pages_crawled')}")
    print(f"  Max depth:    {meta.get('max_depth')}")
    print()
    print(f"  Resources (total):   {summ.get('total_resources', 0)}")
    print(f"  First-party:         {summ.get('first_party_count', 0)}")
    print(f"  Third-party:         {summ.get('third_party_count', 0)}")
    print(f"  Third-party scripts: {summ.get('third_party_script_count', 0)}")
    print(f"  Unique 3P domains:   {summ.get('unique_third_party_domains', 0)}")
    print()
    if summ.get("by_category"):
        print("  By category:")
        for cat, n in sorted(summ["by_category"].items(), key=lambda x: -x[1]):
            print(f"    {cat:<20} {n}")
    if summ.get("by_provider"):
        print()
        print("  Top providers:")
        for prov, n in list(summ["by_provider"].items())[:10]:
            print(f"    {prov:<30} {n}")
    if summ.get("risk_indicators"):
        print()
        print("  Risk indicators:")
        for flag in summ["risk_indicators"]:
            level = flag["level"].upper()
            print(f"    [{level}] {flag['code']}: {flag['description']}")
            examples = flag.get("examples", [])
            if examples:
                print("      Examples:")
                for ex in examples:
                    print(f"        - {ex}")
    risk_score = summ.get("risk_score")
    if risk_score:
        print()
        print(
            "  Risk score:          "
            f"{risk_score.get('score', 0)}/100 ({str(risk_score.get('tier', 'low')).upper()})"
        )
    domain_scores = summ.get("domain_risk_scores", [])
    if domain_scores:
        print("  Top risky domains:")
        for row in domain_scores[:5]:
            print(
                "    "
                f"{row.get('domain')}  "
                f"{row.get('score', 0)}/100 ({str(row.get('tier', 'low')).upper()})"
            )
    print("=" * 60)
    print()
 
 
# Multiple sites
 
def build_aggregate(results: list[dict], run_config: dict | None = None) -> dict:
    """Merge multiple site results into one aggregate report."""
    from collections import defaultdict
    from datetime import datetime, timezone
 
    total_resources = 0
    total_third_party = 0
    total_scripts = 0
    all_domains: set[str] = set()
    category_totals: dict[str, int] = defaultdict(int)
    provider_totals: dict[str, int] = defaultdict(int)
    site_summaries = []
    site_risk_scores: list[dict] = []
    domain_risk_rollup: dict[str, dict] = defaultdict(
        lambda: {
            "domain": "",
            "max_score": 0,
            "average_score": 0.0,
            "site_count": 0,
            "sites": [],
            "sample_categories": set(),
            "sample_providers": set(),
            "_scores": [],
        }
    )
 
    for r in results:
        s = r.get("summary", {})
        total_resources += s.get("total_resources", 0)
        total_third_party += s.get("third_party_count", 0)
        total_scripts += s.get("third_party_script_count", 0)
        all_domains.update(s.get("third_party_domains", []))
        for cat, n in s.get("by_category", {}).items():
            category_totals[cat] += n
        for prov, n in s.get("by_provider", {}).items():
            provider_totals[prov] += n
        risk_score = s.get("risk_score", {})
        if risk_score:
            site_risk_scores.append(
                {
                    "site_domain": r["crawl_metadata"]["site_domain"],
                    "score": int(risk_score.get("score", 0)),
                    "tier": risk_score.get("tier", "low"),
                }
            )
        site_domain = r["crawl_metadata"]["site_domain"]
        for drow in s.get("domain_risk_scores", []):
            domain = drow.get("domain")
            if not domain:
                continue
            agg = domain_risk_rollup[domain]
            agg["domain"] = domain
            score = int(drow.get("score", 0))
            agg["_scores"].append(score)
            agg["max_score"] = max(agg["max_score"], score)
            if site_domain not in agg["sites"]:
                agg["sites"].append(site_domain)
                agg["site_count"] += 1
            category = drow.get("primary_category")
            if category:
                agg["sample_categories"].add(category)
            provider = drow.get("provider")
            if provider:
                agg["sample_providers"].add(provider)
        site_summaries.append({
            "site_domain": r["crawl_metadata"]["site_domain"],
            "target_url": r["crawl_metadata"]["target_url"],
            "third_party_count": s.get("third_party_count", 0),
            "third_party_script_count": s.get("third_party_script_count", 0),
            "unique_third_party_domains": s.get("unique_third_party_domains", 0),
            "by_category": s.get("by_category", {}),
            "risk_score": s.get("risk_score"),
        })
 
    # Domains present across multiple sites
    domain_site_count: dict[str, int] = defaultdict(int)
    for r in results:
        for d in r.get("summary", {}).get("third_party_domains", []):
            domain_site_count[d] += 1
 
    ubiquitous = sorted(
        [(d, c) for d, c in domain_site_count.items() if c > 1],
        key=lambda x: -x[1],
    )

    risk_average = 0.0
    risk_max = 0
    highest_risk_site = None
    if site_risk_scores:
        risk_average = round(sum(row["score"] for row in site_risk_scores) / len(site_risk_scores), 2)
        highest = max(site_risk_scores, key=lambda row: row["score"])
        risk_max = highest["score"]
        highest_risk_site = highest["site_domain"]

    rolled_domains: list[dict] = []
    for row in domain_risk_rollup.values():
        scores = row.pop("_scores")
        row["average_score"] = round(sum(scores) / len(scores), 2) if scores else 0.0
        row["sites"].sort()
        row["sample_categories"] = sorted(row["sample_categories"])
        row["sample_providers"] = sorted(row["sample_providers"])
        rolled_domains.append(row)
    rolled_domains.sort(key=lambda row: (-row["max_score"], -row["site_count"], row["domain"]))
 
    return {
        "report_type": "aggregate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sites_crawled": len(results),
        "run_config": run_config or {},
        "totals": {
            "total_resources": total_resources,
            "total_third_party": total_third_party,
            "total_third_party_scripts": total_scripts,
            "unique_third_party_domains_across_all_sites": len(all_domains),
        },
        "by_category": dict(sorted(category_totals.items(), key=lambda x: -x[1])),
        "by_provider": dict(sorted(provider_totals.items(), key=lambda x: -x[1])),
        "domains_appearing_on_multiple_sites": [
            {"domain": d, "site_count": c} for d, c in ubiquitous
        ],
        "risk_summary": {
            "version": 1,
            "average_score": risk_average,
            "max_score": risk_max,
            "highest_risk_site": highest_risk_site,
            "site_scores": sorted(site_risk_scores, key=lambda row: -row["score"]),
            "domain_scores": rolled_domains,
        },
        "per_site": site_summaries,
    }
 
 
# CLI
 
def parse_args():
    parser = argparse.ArgumentParser(
        description="Security X-Ray: map third-party resources on websites and highlight risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
 
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--url", "-u",
        action="append",
        dest="urls",
        metavar="URL",
        help="Target URL to crawl (can be repeated for multiple sites).",
    )
    target_group.add_argument(
        "--targets", "-t",
        metavar="FILE",
        help="Path to a text file with one URL per line.",
    )
 
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=1,
        metavar="N",
        help="Max link-follow depth (0 = homepage only, 1 = homepage + linked pages, …). Default: 1.",
    )
    parser.add_argument(
        "--output", "-o",
        default="./output",
        metavar="DIR",
        help="Directory to write JSON output files. Default: ./output",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=20,
        metavar="N",
        help="Max pages to crawl per site. Default: 20.",
    )
    parser.add_argument(
        "--max-internal-links",
        type=int,
        default=30,
        metavar="N",
        help="Max internal links followed from each crawled page. Default: 30.",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=1.2,
        metavar="SECONDS",
        help="Minimum seconds between requests to the same host. Default: 1.2.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        metavar="SECONDS",
        help="HTTP request timeout in seconds. Default: 15.",
    )
    parser.add_argument(
        "--aggregate",
        action="store_true",
        help="Write _aggregate.json and aggregate_graph.json (bundle for offline graphing).",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Write graph_preview.html; with --aggregate uses aggregate_graph.json, else per-site JSON.",
    )
    parser.add_argument(
        "--graph-open",
        action="store_true",
        help="When used with --graph, open generated graph HTML in the browser.",
    )
    parser.add_argument(
        "--graph-width",
        type=int,
        metavar="PX",
        help="When used with --graph, set fixed graph width in pixels.",
    )
    parser.add_argument(
        "--graph-height",
        type=int,
        metavar="PX",
        help="When used with --graph, set fixed graph height in pixels.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Stop per-site summary output.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
 
    return parser.parse_args()
 
 
def main():
    args = parse_args()
 
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.depth < 0:
        logger.error("--depth must be >= 0")
        return 1
    if args.max_pages < 1:
        logger.error("--max-pages must be >= 1")
        return 1
    if args.max_internal_links < 1:
        logger.error("--max-internal-links must be >= 1")
        return 1
    if args.timeout < 1:
        logger.error("--timeout must be >= 1")
        return 1
    if args.rate_limit < 0:
        logger.error("--rate-limit must be >= 0")
        return 1
    if args.graph_width is not None and args.graph_width < 1:
        logger.error("--graph-width must be >= 1")
        return 1
    if args.graph_height is not None and args.graph_height < 1:
        logger.error("--graph-height must be >= 1")
        return 1
    if args.graph_open and not args.graph:
        logger.error("--graph-open requires --graph")
        return 1
 
    # Build target list
    if args.targets:
        targets = load_targets(args.targets)
    else:
        targets = [ensure_https(u) for u in args.urls]
 
    if not targets:
        logger.error("No targets found. Exiting.")
        sys.exit(1)
 
    logger.info("Starting Security X-Ray for %d site(s) at depth %d", len(targets), args.depth)
 
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
 
    # Shared state
    session = requests.Session()
    session.headers["User-Agent"] = "SecurityXRayCrawler/1.0"
    rate_limiter = RateLimiter(delay=args.rate_limit)
    robots_cache = RobotsCache(session=session, timeout=args.timeout)
 
    crawler = SiteCrawler(
        rate_limiter=rate_limiter,
        robots_cache=robots_cache,
        timeout=args.timeout,
        max_pages_per_site=args.max_pages,
        max_internal_links_per_page=args.max_internal_links,
    )
 
    all_results: list[dict] = []
    result_paths: list[Path] = []
    failed: list[str] = []
 
    for i, url in enumerate(targets, 1):
        logger.info("[%d/%d] Crawling %s ...", i, len(targets), url)
        try:
            result = crawler.crawl(url, max_depth=args.depth)
            all_results.append(result)
 
            fname = safe_filename(url) + ".json"
            result_path = output_dir / fname
            write_json(result, result_path)
            result_paths.append(result_path)
 
            if not args.quiet:
                print_summary(result)
 
        except KeyboardInterrupt:
            logger.warning("Interrupted by user.")
            break
        except Exception as e:
            logger.error("Failed to crawl %s: %s", url, e, exc_info=args.verbose)
            failed.append(url)
 
    # Aggregate report
    if args.aggregate and all_results:
        run_config = {
            "depth": args.depth,
            "max_pages": args.max_pages,
            "max_internal_links": args.max_internal_links,
            "rate_limit_seconds": args.rate_limit,
            "timeout_seconds": args.timeout,
            "targets": targets,
        }
        agg = build_aggregate(all_results, run_config=run_config)
        write_json(agg, output_dir / "_aggregate.json")
        logger.info("Aggregate report written to %s/_aggregate.json", output_dir)
        graph_data = {
            "format_version": 1,
            "report_type": "aggregate_graph",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_config": run_config,
            "aggregate_summary": agg,
            "crawl_results": all_results,
        }
        write_json(graph_data, output_dir / "aggregate_graph.json")
        logger.info("Aggregate graph bundle written to %s/aggregate_graph.json", output_dir)

    # Always refresh unknown-domain review queue after crawling.
    if all_results:
        update_unknown_candidates(
            all_results,
            Path("data") / "classification_candidates.json",
        )

    # Optional graph output: exactly one graph per run.
    if args.graph and result_paths:
        graph_path = output_dir / "graph_preview.html"
        agg_graph_path = output_dir / "aggregate_graph.json"
        if args.aggregate and all_results and agg_graph_path.exists():
            generate_graph_from_input(
                input_path=agg_graph_path,
                graph_output_path=graph_path,
                open_browser=args.graph_open,
                width=args.graph_width,
                height=args.graph_height,
            )
        else:
            generate_graph_from_reports(
                report_paths=result_paths,
                graph_output_path=graph_path,
                open_browser=args.graph_open,
                width=args.graph_width,
                height=args.graph_height,
            )

    # Final status
    logger.info("Done. %d site(s) crawled successfully, %d failed.", len(all_results), len(failed))
    if failed:
        logger.warning("Failed sites: %s", ", ".join(failed))
 
    return 0 if not failed else 1
 
 
if __name__ == "__main__":
    sys.exit(main())
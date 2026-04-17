""" 
Example Inputs:
  # Single site, default depth 1
  python main.py --url https://example.com
 
  # Multiple sites from a file, depth 2, custom output dir
  python main.py --targets targets.txt --depth 2 --output ./results
 
  # Multiple URLs inline
  python main.py --url https://bbc.com --url https://nytimes.com --depth 1
 
  # Combine all site results into one aggregate JSON
  python main.py --targets targets.txt --depth 1 --aggregate
"""
 
from __future__ import annotations
 
import argparse
import json
import logging
import os
import re
import sys
import time
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
    print("=" * 60)
    print()
 
 
# Multiple sites
 
def build_aggregate(results: list[dict]) -> dict:
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
        site_summaries.append({
            "site_domain": r["crawl_metadata"]["site_domain"],
            "target_url": r["crawl_metadata"]["target_url"],
            "third_party_count": s.get("third_party_count", 0),
            "third_party_script_count": s.get("third_party_script_count", 0),
            "unique_third_party_domains": s.get("unique_third_party_domains", 0),
            "by_category": s.get("by_category", {}),
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
 
    return {
        "report_type": "aggregate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sites_crawled": len(results),
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
        help="Also write a combined aggregate report across all crawled sites.",
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
    )
 
    all_results: list[dict] = []
    failed: list[str] = []
 
    for i, url in enumerate(targets, 1):
        logger.info("[%d/%d] Crawling %s ...", i, len(targets), url)
        try:
            result = crawler.crawl(url, max_depth=args.depth)
            all_results.append(result)
 
            fname = safe_filename(url) + ".json"
            write_json(result, output_dir / fname)
 
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
        agg = build_aggregate(all_results)
        write_json(agg, output_dir / "_aggregate.json")
        logger.info("Aggregate report written to %s/_aggregate.json", output_dir)
 
    # Final status
    logger.info("Done. %d site(s) crawled successfully, %d failed.", len(all_results), len(failed))
    if failed:
        logger.warning("Failed sites: %s", ", ".join(failed))
 
    return 0 if not failed else 1
 
 
if __name__ == "__main__":
    sys.exit(main())
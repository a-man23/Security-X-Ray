"""
Generate actionable suggestions for improving domain classification rules.

Scans crawl outputs in ./output, finds third-party resources still labeled as "unknown",
and writes a ranked review file you can use to update data/domain_classifications.json safely.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Suggest classifier additions from unknown third-party domains."
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory containing per-site crawl JSON files. Default: ./output",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=2,
        help="Only include domains seen at least N times. Default: 2",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=100,
        help="Maximum number of suggested domains to include. Default: 100",
    )
    parser.add_argument(
        "--report-file",
        default="output/classifier_suggestions.md",
        help="Where to write the markdown report. Default: output/classifier_suggestions.md",
    )
    return parser.parse_args()


def iter_site_reports(output_dir: Path):
    for path in sorted(output_dir.glob("*.json")):
        if path.name.startswith("_"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "summary" in data and "resources" in data:
                yield path, data
        except Exception:
            continue


def build_report(output_dir: Path, min_count: int, top_n: int) -> str:
    domain_counts: dict[str, int] = defaultdict(int)
    domain_sites: dict[str, set[str]] = defaultdict(set)
    domain_examples: dict[str, list[str]] = defaultdict(list)
    total_reports = 0

    for _path, report in iter_site_reports(output_dir):
        total_reports += 1
        site = report.get("crawl_metadata", {}).get("site_domain", "unknown-site")
        for res in report.get("resources", []):
            if res.get("party") != "third-party":
                continue
            if res.get("category") != "unknown":
                continue
            domain = res.get("registrable_domain")
            url = res.get("url")
            if not domain:
                continue
            domain_counts[domain] += 1
            domain_sites[domain].add(site)
            if url and len(domain_examples[domain]) < 3 and url not in domain_examples[domain]:
                domain_examples[domain].append(url)

    ranked = sorted(
        (
            {
                "domain": d,
                "count": c,
                "site_count": len(domain_sites[d]),
                "sites": sorted(domain_sites[d]),
                "examples": domain_examples[d],
            }
            for d, c in domain_counts.items()
            if c >= min_count
        ),
        key=lambda x: (-x["site_count"], -x["count"], x["domain"]),
    )[:top_n]

    lines: list[str] = []
    lines.append("# Classifier Suggestions")
    lines.append("")
    lines.append(
        f"Scanned `{total_reports}` report(s) in `{output_dir.as_posix()}` and found "
        f"`{len(domain_counts)}` unknown third-party domain(s)."
    )
    lines.append(
        f"This list includes domains seen at least `{min_count}` time(s), up to `{top_n}` entries."
    )
    lines.append("")
    lines.append("## How to use")
    lines.append("")
    lines.append("1. Review each domain manually (vendor docs, reputation, service purpose).")
    lines.append("2. Add high-confidence entries to `data/domain_classifications.json`.")
    lines.append("3. Re-run crawl and verify unknown count decreases without obvious mislabels.")
    lines.append("")
    lines.append("## Suggested domains")
    lines.append("")

    if not ranked:
        lines.append("No domains met the threshold.")
        lines.append("")
        return "\n".join(lines)

    lines.append("| Domain | Seen | Sites | Example URLs |")
    lines.append("|---|---:|---:|---|")
    for row in ranked:
        examples = "<br>".join(row["examples"]) if row["examples"] else "-"
        lines.append(
            f"| `{row['domain']}` | {row['count']} | {row['site_count']} | {examples} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    report_file = Path(args.report_file)

    if args.min_count < 1:
        raise SystemExit("--min-count must be >= 1")
    if args.top < 1:
        raise SystemExit("--top must be >= 1")
    if not output_dir.exists():
        raise SystemExit(f"Output directory does not exist: {output_dir}")

    report = build_report(output_dir=output_dir, min_count=args.min_count, top_n=args.top)
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(report, encoding="utf-8")
    print(f"Wrote suggestions report: {report_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Promote reviewed classification candidates into domain_classifications.json.

Workflow:
1. Edit data/classification_candidates.json and set:
   - status: "approved"
   - proposed_category: "<valid category>"
   - proposed_provider: "<provider name>" (or null)
2. Run this script to merge approved entries into data/domain_classifications.json
3. Promoted entries are marked with status "promoted" in candidates file.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


VALID_CATEGORIES = {
    "analytics",
    "advertising",
    "cdn",
    "social",
    "support",
    "ab_testing",
    "tag_manager",
    "security",
    "consent",
    "payments",
    "fonts",
    "unknown",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Promote approved classification candidates into canonical domain map."
    )
    parser.add_argument(
        "--candidates",
        default="data/classification_candidates.json",
        help="Path to classification candidates JSON.",
    )
    parser.add_argument(
        "--classifications",
        default="data/domain_classifications.json",
        help="Path to canonical domain classifications JSON.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, runs in dry-run mode.",
    )
    return parser.parse_args()


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_domain(domain: str) -> str:
    return domain.strip().lower()


def main() -> int:
    args = parse_args()
    candidates_path = Path(args.candidates)
    classifications_path = Path(args.classifications)

    candidates_doc = load_json(candidates_path, {"format_version": 1, "domains": {}})
    domains = candidates_doc.get("domains", {})
    if not isinstance(domains, dict):
        raise SystemExit(f"Invalid candidates format in {candidates_path}")

    classifications = load_json(classifications_path, {})
    if not isinstance(classifications, dict):
        raise SystemExit(f"Invalid classifications format in {classifications_path}")

    promoted: list[tuple[str, str, str | None]] = []
    skipped: list[tuple[str, str]] = []

    for raw_domain, row in domains.items():
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        if status != "approved":
            continue

        category = row.get("proposed_category")
        provider = row.get("proposed_provider")
        domain = normalize_domain(raw_domain)

        if not isinstance(category, str) or category not in VALID_CATEGORIES:
            skipped.append((domain, "invalid or missing proposed_category"))
            continue
        if provider is not None and not isinstance(provider, str):
            skipped.append((domain, "proposed_provider must be string or null"))
            continue

        classifications[domain] = {"category": category, "provider": provider}
        row["status"] = "promoted"
        row["promoted_at"] = datetime.now(timezone.utc).isoformat()
        promoted.append((domain, category, provider))

    print(f"Approved entries found: {len(promoted) + len(skipped)}")
    print(f"Ready to promote: {len(promoted)}")
    if skipped:
        print(f"Skipped: {len(skipped)}")
        for domain, reason in skipped[:20]:
            print(f"  - {domain}: {reason}")

    if not promoted:
        print("No approved candidates to promote.")
        return 0

    if not args.apply:
        print("")
        print("Dry run only. Re-run with --apply to write files.")
        for domain, category, provider in promoted[:30]:
            print(f"  + {domain} -> category={category}, provider={provider}")
        return 0

    classifications_path.parent.mkdir(parents=True, exist_ok=True)
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    classifications_path.write_text(
        json.dumps(dict(sorted(classifications.items())), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    candidates_doc["last_updated"] = datetime.now(timezone.utc).isoformat()
    candidates_path.write_text(
        json.dumps(candidates_doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("")
    print(f"Promoted {len(promoted)} entries into {classifications_path}")
    print(f"Updated candidate statuses in {candidates_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

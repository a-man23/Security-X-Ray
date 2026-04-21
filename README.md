# Security-X-Ray

Security X-Ray is a lightweight crawler that maps first-party and third-party web resources
to help analyze client-side security and privacy risk.

This repository currently covers the crawler and data pipeline work from the project
proposal/progress report. Graph visualization is intentionally not implemented yet.

## What It Does

- Crawls one or more websites from CLI input (`--url`) or a targets file (`--targets`)
- Respects `robots.txt` and applies per-host rate limiting
- Follows internal links up to a configurable depth and breadth
- Extracts resource URLs from `script`, `iframe`, `img`, `link`, and `source` tags
- Normalizes URLs to registrable domains (eTLD+1)
- Classifies resources as first-party vs third-party
- Applies heuristic/list-based provider categories (analytics, advertising, cdn, etc.)
- Emits per-site JSON reports and an optional aggregate report

## Requirements

- Python 3.10+ recommended
- Dependencies in `requirements.txt`

Install:

```bash
pip install -r requirements.txt
```

## Usage

Single site:

```bash
python main.py --url https://example.com
```

Multiple sites from file:

```bash
python main.py --targets targets.txt --depth 2 --output ./output
```

Multiple URLs inline:

```bash
python main.py --url https://bbc.com --url https://nytimes.com --depth 1
```

With aggregate output:

```bash
python main.py --targets targets.txt --aggregate
```

Tune crawl depth/breadth:

```bash
python main.py --targets targets.txt --depth 2 --max-pages 25 --max-internal-links 20
```

## CLI Flags

- `--url` / `-u`: target URL (repeatable)
- `--targets` / `-t`: file with one URL per line
- `--depth` / `-d`: max internal-link depth per site (default `1`)
- `--max-pages`: max pages crawled per site (default `20`)
- `--max-internal-links`: max internal links followed from each page (default `30`)
- `--rate-limit`: minimum delay between requests to same host in seconds (default `1.2`)
- `--timeout`: HTTP timeout in seconds (default `15`)
- `--output` / `-o`: output directory (default `./output`)
- `--aggregate`: write combined `_aggregate.json`
- `--quiet` / `-q`: suppress per-site terminal summaries
- `--verbose` / `-v`: enable debug logging

## Output Files

Per-site report:

- `crawl_metadata`: target URL, site domain, crawl parameters, pages crawled
- `summary`: totals, third-party categories/providers, domain list, risk indicators
- `resources`: deduplicated resource records with classification
- `pages`: page-level crawl status, extracted resources, discovered internal links

Optional aggregate report:

- `_aggregate.json`: cross-site totals, category/provider breakdowns, shared domains,
  and `run_config` (crawl settings used for that run)

## Alias Handling for Owned Domains

Some organizations load assets from domains they also control (for example, news
properties using multiple related domains). To avoid false third-party labeling, add
aliases in:

- `data/aliases.json`

Format:

```json
{
  "alias-domain.com": "primary-site.com"
}
```

## Robots.txt Policy

The crawler enforces robots rules per host (`scheme + host + port`) and checks permission
before every page fetch.

- Redirect-aware enforcement: each redirect hop is checked against that destination host's
  `robots.txt` (up to 5 redirects)
- `robots.txt` status handling:
  - `2xx`: parse and enforce returned rules
  - `4xx` except `429`: treated as "no robots restrictions"
  - `429` and `5xx`: crawl is denied for safety
  - network/DNS/timeout errors fetching `robots.txt`: crawl is denied for safety
- If a URL is disallowed, page status is recorded as `blocked_by_robots`

## Current Limitations

- Static HTML only: resources loaded dynamically after JavaScript execution are not seen
- No browser instrumentation or runtime JS execution (intentional for safety/simplicity)
- Heuristic classification is useful but not perfect; unknown domains need manual review

## Next Planned Step

- Convert JSON crawl output into graph-ready structures for visualization (not implemented yet)

# Security-X-Ray

Security X-Ray is a lightweight crawler that maps first-party and third-party web resources
to help analyze client-side security and privacy risk.

This repository currently covers the crawler and data pipeline work from the project
proposal/progress report, including an optional interactive graph preview in the browser.

## What It Does

- Crawls one or more websites from CLI input (`--url`) or a targets file (`--targets`)
- Respects `robots.txt` and applies per-host rate limiting
- Follows internal links up to a configurable depth and breadth
- Extracts resource URLs from `script`, `iframe`, `img`, `link`, and `source` tags
- Normalizes URLs to registrable domains (eTLD+1)
- Classifies resources as first-party vs third-party
- Applies heuristic/list-based provider categories (analytics, advertising, cdn, etc.)
- Emits per-site JSON reports and an optional aggregate report
- Auto-updates `data/classification_candidates.json` with unknown third-party domains to review

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

Classifier improvement helper:

- `output/classifier_suggestions.md`: generated review list of unknown third-party domains
  ranked by frequency/site coverage (see command below)
- `data/classification_candidates.json`: auto-maintained queue of unknown domains discovered
  during normal crawls

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

## Practical Classifier Workflow

Use this workflow to improve classification accuracy without importing noisy giant lists:

1. Crawl your target set and generate JSON in `output/`
2. Generate suggestions from unknown third-party domains:

```bash
python scripts/suggest_classifications.py --min-count 2 --top 100
```

3. Review `output/classifier_suggestions.md`
4. Add only high-confidence mappings to `data/domain_classifications.json`
5. Re-run crawl and compare unknown counts

Optional promotion workflow (from candidate queue):

1. Edit `data/classification_candidates.json` entries and set:
   - `status: "approved"`
   - `proposed_category: "<valid category>"`
   - `proposed_provider: "<provider or null>"`
2. Preview promotions (dry run):

```bash
python scripts/promote_candidates.py
```

3. Apply promotions:

```bash
python scripts/promote_candidates.py --apply
```

## Graph visualization (browser)

After crawling, generate an interactive graph as HTML and open it in your **default browser**.
The page uses the **full viewport**. Layout starts **top-down**, then you can **drag nodes freely**.
The **crawl hub** uses the same dot shape as leaves (larger) and **category** diamonds show **counts** inside (fixed node sizes,
hub slightly larger than diamonds); **leaf** dots are fixed size with **domain only** under
the dot. **Diamond → domain** edges show the
resource **count** beside the line (upright, not tilted with the edge) and scale in thickness. Hover tooltips stay plain text (no raw HTML).

Requires: `pip install -r requirements.txt` (adds `pyvis`).

```bash
python scripts/visualize_graph.py --input output/cnn.com.json
```

Writes `output/graph_preview.html` by default and opens it. Optional fixed size in pixels (default is full window):

```bash
python scripts/visualize_graph.py -i output/nytimes.com.json --width 1100 --height 720
```

Write HTML only without launching the browser:

```bash
python scripts/visualize_graph.py -i output/cnn.com.json --no-open
```

## Next Planned Step

- Extend graph mode (aggregate multi-site, filter by category, export PNG/SVG)

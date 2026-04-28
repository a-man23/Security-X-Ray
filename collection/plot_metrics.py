"""
Generate paper-ready plots from collection/output metrics.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot key Security X-Ray dataset metrics.")
    p.add_argument(
        "--input-dir",
        type=Path,
        default=Path("collection") / "output",
        help="Directory produced by collection/collect_metrics.py",
    )
    p.add_argument(
        "--dest",
        type=Path,
        default=Path("collection") / "plots",
        help="Directory where plot images are written.",
    )
    return p.parse_args()


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _save(fig: plt.Figure, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_site_footprint(site_rows: list[dict], dest: Path) -> None:
    if not site_rows:
        return
    sites = [r["site_domain"] for r in site_rows]
    third_party = [int(r["third_party_count"]) for r in site_rows]
    scripts = [int(r["third_party_script_count"]) for r in site_rows]

    fig, ax = plt.subplots(figsize=(16, 6))
    x = range(len(sites))
    ax.bar(x, third_party, label="Third-party resources", color="#5DA5DA")
    ax.bar(x, scripts, label="Third-party scripts", color="#F15854")
    ax.set_title("Per-site Dependency Footprint")
    ax.set_ylabel("Count")
    ax.set_xticks(list(x))
    ax.set_xticklabels(sites, rotation=35, ha="right", fontsize=9)
    ax.margins(x=0.01)
    ax.legend()
    _save(fig, dest / "site_dependency_footprint.png")


def plot_top_shared_domains(shared_rows: list[dict], dest: Path, top_n: int = 20) -> None:
    top = shared_rows[:top_n]
    if not top:
        return
    domains = [r["domain"] for r in top]
    counts = [int(r["site_count"]) for r in top]

    fig, ax = plt.subplots(figsize=(11, 7))
    ax.barh(domains[::-1], counts[::-1], color="#60BD68")
    ax.set_title(f"Top {len(top)} Shared Third-Party Domains")
    ax.set_xlabel("Number of sites where domain appears")
    _save(fig, dest / "top_shared_domains.png")


def plot_site_overlap_matrix(overlap_rows: list[dict], dest: Path) -> None:
    if not overlap_rows:
        return
    sites = [r["site_domain"] for r in overlap_rows]
    matrix: list[list[float]] = []
    for r in overlap_rows:
        matrix.append([float(int(r[s])) for s in sites])

    arr = np.array(matrix, dtype=float)
    if arr.size == 0:
        return

    # Treat diagonal (self-overlap) as not comparable for color scaling/interpretation.
    for i in range(min(arr.shape[0], arr.shape[1])):
        arr[i, i] = -1.0

    off_diag = arr[arr >= 0]
    vmax = float(off_diag.max()) if off_diag.size else 1.0

    fig, ax = plt.subplots(figsize=(13, 11))
    cmap = plt.cm.Blues.copy()
    cmap.set_under("black")  # diagonal/self-overlap
    im = ax.imshow(arr, cmap=cmap, vmin=0, vmax=vmax)
    ax.set_title("Site Overlap Matrix (shared third-party domains)\n(diagonal = self overlap)")
    ax.set_xticks(range(len(sites)))
    ax.set_yticks(range(len(sites)))
    ax.set_xticklabels(sites, rotation=40, ha="right", fontsize=9)
    ax.set_yticklabels(sites, fontsize=10)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    _save(fig, dest / "site_overlap_matrix.png")


def plot_risk_distributions(site_rows: list[dict], domain_rows: list[dict], dest: Path) -> None:
    site_scores = [int(r["risk_score"]) for r in site_rows]
    domain_scores = [int(r["max_score"]) for r in domain_rows]
    if not site_scores and not domain_scores:
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    if site_scores:
        axes[0].hist(site_scores, bins=10, color="#B276B2", edgecolor="black")
    axes[0].set_title("Site Risk Score Distribution")
    axes[0].set_xlabel("Risk score")
    axes[0].set_ylabel("Frequency")

    if domain_scores:
        axes[1].hist(domain_scores, bins=10, color="#FAA43A", edgecolor="black")
    axes[1].set_title("Domain Risk Score Distribution (max across sites)")
    axes[1].set_xlabel("Risk score")
    axes[1].set_ylabel("Frequency")
    _save(fig, dest / "risk_score_distributions.png")


def plot_category_composition(site_category_rows: list[dict], dest: Path, top_categories: int = 6) -> None:
    if not site_category_rows:
        return
    site_order = sorted({r["site_domain"] for r in site_category_rows})
    category_totals: defaultdict[str, int] = defaultdict(int)
    by_site_cat: defaultdict[tuple[str, str], int] = defaultdict(int)
    for r in site_category_rows:
        site = r["site_domain"]
        cat = r["category"]
        count = int(r["count"])
        category_totals[cat] += count
        by_site_cat[(site, cat)] += count

    top_cats = [c for c, _ in sorted(category_totals.items(), key=lambda kv: -kv[1])[:top_categories]]
    if not top_cats:
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    x = list(range(len(site_order)))
    bottom = [0] * len(site_order)
    for cat in top_cats:
        values = [by_site_cat[(site, cat)] for site in site_order]
        ax.bar(x, values, bottom=bottom, label=cat)
        bottom = [bottom[i] + values[i] for i in range(len(values))]

    ax.set_title("Per-site Category Composition")
    ax.set_ylabel("Resource count")
    ax.set_xticks(x)
    ax.set_xticklabels(site_order, rotation=30, ha="right")
    ax.legend(loc="upper right", fontsize=8)
    _save(fig, dest / "site_category_composition.png")


def main() -> int:
    args = parse_args()
    inp = args.input_dir
    dest = args.dest

    site_rows = read_csv(inp / "site_metrics.csv")
    shared_rows = read_csv(inp / "shared_domains.csv")
    overlap_rows = read_csv(inp / "site_overlap_matrix.csv")
    domain_rows = read_csv(inp / "domain_risk_rollup.csv")
    site_category_rows = read_csv(inp / "site_category_counts.csv")

    plot_site_footprint(site_rows, dest)
    plot_top_shared_domains(shared_rows, dest, top_n=20)
    plot_site_overlap_matrix(overlap_rows, dest)
    plot_risk_distributions(site_rows, domain_rows, dest)
    plot_category_composition(site_category_rows, dest, top_categories=6)

    print(f"Wrote plots to {dest.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

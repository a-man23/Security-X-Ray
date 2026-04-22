"""
Interactive third-party dependency graph from a Security X-Ray crawl JSON.

Writes HTML (PyVis) and opens it in your default web browser: fullscreen canvas,
initial top-down layout then free drag; hub (dot, like leaves) + category diamonds show counts in canvas
(fixed node sizes); leaf dots fixed with domain under; diamond→leaf edges show counts and
scale in thickness; no corner navigation buttons.
"""

from __future__ import annotations

import argparse
import json
import webbrowser
from collections import defaultdict
from pathlib import Path

from pyvis.network import Network


# Category -> node color (hex)
CATEGORY_COLORS: dict[str, str] = {
    "first-party": "#4a90d9",
    "analytics": "#7cb342",
    "advertising": "#e53935",
    "cdn": "#9575cd",
    "social": "#26c6da",
    "support": "#ffb74d",
    "ab_testing": "#ec407a",
    "tag_manager": "#78909c",
    "security": "#5c6bc0",
    "consent": "#8d6e63",
    "payments": "#66bb6a",
    "fonts": "#9ccc65",
    "unknown": "#90a4ae",
}

# vis-network `size` ≈ diameter; all category diamonds match a former "count 1" diamond.
_DIAMOND_NODE_SIZE = 36
_HUB_NODE_SIZE = _DIAMOND_NODE_SIZE + 10


def _category_node_id(category: str) -> str:
    """Internal id; should not overlap real registrable domains."""
    return f"__sxr_cat__{category}"


# Overrides for classifier slugs where .title() is wrong (e.g. cdn -> "Cdn").
_CATEGORY_LABEL_PRETTY: dict[str, str] = {
    "cdn": "CDN",
    "ab_testing": "A/B Testing",
}


def _category_display_name(category: str) -> str:
    if category in _CATEGORY_LABEL_PRETTY:
        return _CATEGORY_LABEL_PRETTY[category]
    return category.replace("_", " ").title()


def _plain_tip(*lines: str) -> str:
    """vis-network shows node/edge `title` as plain text; HTML tags appear literally."""
    return "\n".join(lines)


def _finalize_pyvis_html(html: str) -> str:
    """Fill the browser tab: reset margins and stretch the network container."""
    html = html.replace(
        '<meta charset="utf-8">',
        '<meta charset="utf-8">\n        <meta name="viewport" content="width=device-width, initial-scale=1">',
        1,
    )
    inject = """
            html, body { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; }
            .card { margin: 0 !important; border: none !important; box-shadow: none !important; max-width: none !important; }
            .card-body { padding: 0 !important; height: 100vh; }
            #mynetwork { border: none !important; float: none !important; box-sizing: border-box; }
"""
    if '<style type="text/css">' in html:
        html = html.replace('<style type="text/css">', '<style type="text/css">' + inject, 1)

    # Hub + diamond counts (canvas); captions under all nodes that set sxr_caption. Then drop hierarchical lock for free drag.
    hook = """
                  (function () {
                    var __sxrRel = false;
                    network.on("afterDrawing", function (ctx) {
                      try {
                        var list = nodes.get();
                        ctx.save();
                        ctx.textAlign = "center";
                        for (var i = 0; i < list.length; i++) {
                          var n = list[i];
                          var box = network.getBoundingBox(n.id);
                          if (!box || box.left === undefined) continue;
                          var cx = (box.left + box.right) / 2;
                          if (n.sxr_inner_count !== undefined && n.sxr_inner_count !== null) {
                            var w = box.right - box.left;
                            var h = box.bottom - box.top;
                            var fs = Math.max(13, Math.min(30, Math.min(w, h) * 0.44));
                            ctx.font = "600 " + fs + "px Segoe UI, Arial, sans-serif";
                            ctx.fillStyle = "#f7f7f7";
                            ctx.textBaseline = "middle";
                            ctx.fillText(String(n.sxr_inner_count), cx, (box.top + box.bottom) / 2);
                          }
                          if (n.sxr_caption) {
                            ctx.font = "12px Segoe UI, Arial, sans-serif";
                            ctx.fillStyle = "#d8d8d8";
                            ctx.textBaseline = "top";
                            var cy = box.bottom + 6;
                            var txt = String(n.sxr_caption);
                            var maxW = Math.max(160, (box.right - box.left) * 2.2);
                            while (txt.length > 1 && ctx.measureText(txt + "...").width > maxW) {
                              txt = txt.slice(0, -1);
                            }
                            if (txt !== String(n.sxr_caption)) txt += "...";
                            ctx.fillText(txt, cx, cy);
                          }
                        }
                        var elist = edges.get();
                        for (var j = 0; j < elist.length; j++) {
                          var ed = elist[j];
                          if (ed.sxr_edge_label === undefined || ed.sxr_edge_label === null) continue;
                          var bFrom = network.getBoundingBox(ed.from);
                          var bTo = network.getBoundingBox(ed.to);
                          if (!bFrom || !bTo || bFrom.left === undefined) continue;
                          var c1x = (bFrom.left + bFrom.right) / 2;
                          var c1y = (bFrom.top + bFrom.bottom) / 2;
                          var c2x = (bTo.left + bTo.right) / 2;
                          var c2y = (bTo.top + bTo.bottom) / 2;
                          var ex = (c1x + c2x) / 2;
                          var ey = (c1y + c2y) / 2;
                          ctx.font = "600 16px Segoe UI, Arial, sans-serif";
                          ctx.textAlign = "center";
                          ctx.textBaseline = "middle";
                          var et = String(ed.sxr_edge_label);
                          ctx.strokeStyle = "#1a1a1a";
                          ctx.lineWidth = 4;
                          ctx.lineJoin = "round";
                          ctx.miterLimit = 2;
                          ctx.strokeText(et, ex, ey);
                          ctx.fillStyle = "#f0f0f0";
                          ctx.fillText(et, ex, ey);
                        }
                        ctx.restore();
                        if (!__sxrRel) {
                          __sxrRel = true;
                          setTimeout(function () {
                            try {
                              network.setOptions({
                                layout: { hierarchical: { enabled: false } },
                                physics: { enabled: false }
                              });
                            } catch (e2) {}
                          }, 80);
                        }
                      } catch (e) {}
                    });
                  })();
"""
    marker = "network = new vis.Network(container, data, options);"
    if marker in html:
        html = html.replace(marker, marker + hook, 1)
    return html


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Visualize crawl output as an interactive domain graph in the browser.")
    p.add_argument(
        "--input",
        "-i",
        required=True,
        type=Path,
        help="Path to a per-site crawl JSON (e.g. output/cnn.com.json).",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("output") / "graph_preview.html",
        help="Where to write the HTML file. Default: output/graph_preview.html",
    )
    p.add_argument(
        "--no-open",
        action="store_true",
        help="Write HTML only; do not launch the default browser.",
    )
    p.add_argument(
        "--width",
        type=int,
        default=None,
        metavar="PX",
        help="Fixed width in pixels; default is full viewport (100vw).",
    )
    p.add_argument(
        "--height",
        type=int,
        default=None,
        metavar="PX",
        help="Fixed height in pixels; default is full viewport (100vh).",
    )
    return p.parse_args()


def load_crawl(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "crawl_metadata" not in data:
        raise SystemExit(f"Not a valid crawl JSON: {path}")
    return data


def build_graph(data: dict, width: int | None, height: int | None) -> str:
    site = data["crawl_metadata"]["site_domain"]
    title = data["crawl_metadata"].get("target_url", site)
    wstr = f"{width}px" if width is not None else "100vw"
    hstr = f"{height}px" if height is not None else "100vh"

    edge_meta: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"count": 0, "tags": defaultdict(int), "providers": set(), "categories": set()}
    )

    for res in data.get("resources", []):
        if res.get("party") != "third-party":
            continue
        d = res.get("registrable_domain")
        if not d:
            continue
        key = (site, d)
        edge_meta[key]["count"] += 1
        edge_meta[key]["tags"][res.get("tag", "?")] += 1
        if res.get("provider"):
            edge_meta[key]["providers"].add(res["provider"])
        edge_meta[key]["categories"].add(res.get("category", "unknown"))

    grand_total = sum(m["count"] for m in edge_meta.values())

    net = Network(
        height=hstr,
        width=wstr,
        bgcolor="#1e1e1e",
        font_color="#e0e0e0",
        directed=True,
    )
    # site → category hub → domain (hierarchical top-down).
    net.set_options(
        """
        {
          "layout": {
            "hierarchical": {
              "enabled": true,
              "direction": "UD",
              "sortMethod": "directed",
              "levelSeparation": 160,
              "nodeSpacing": 100,
              "treeSpacing": 180
            }
          },
          "nodes": {
            "chosen": false,
            "font": { "size": 14, "face": "Segoe UI, sans-serif", "align": "center" },
            "borderWidth": 2,
            "shadow": true
          },
          "edges": {
            "arrows": "to",
            "smooth": { "type": "cubicBezier", "forceDirection": "vertical" },
            "scaling": { "enabled": true, "min": 1, "max": 16, "label": { "enabled": true, "min": 11, "max": 16 } },
            "font": { "size": 12, "align": "middle", "color": "#f0f0f0", "strokeWidth": 3, "strokeColor": "#1a1a1a" }
          },
          "physics": { "enabled": false },
          "interaction": {
            "hover": true,
            "tooltipDelay": 150,
            "navigationButtons": false,
            "dragNodes": true,
            "dragView": true
          }
        }
        """
    )

    # Per third-party domain: primary category + full edge metadata (one row per domain).
    domain_rows: list[tuple[str, dict, str]] = []
    for (src, dst), meta in edge_meta.items():
        assert src == site
        primary_cat = sorted(meta["categories"], key=lambda c: (c != "unknown", c))[0]
        domain_rows.append((dst, meta, primary_cat))

    domain_rows.sort(key=lambda x: (-x[1]["count"], x[2], x[0]))

    # Category hub nodes + resource totals for tooltips / edge labels.
    cat_domains: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    cat_resource_total: dict[str, int] = defaultdict(int)
    for dst, meta, primary_cat in domain_rows:
        cat_domains[primary_cat].append((dst, meta))
        cat_resource_total[primary_cat] += meta["count"]

    res_word = "third-party resource" if grand_total == 1 else "third-party resources"
    net.add_node(
        site,
        label="\u200b",
        sxr_inner_count=grand_total,
        sxr_caption=site,
        title=_plain_tip(site, "First-party · crawl hub", f"{grand_total} {res_word} (sum of edges below)", title),
        color=CATEGORY_COLORS["first-party"],
        size=_HUB_NODE_SIZE,
        shape="dot",
        font={"size": 1, "face": "Segoe UI, sans-serif", "color": CATEGORY_COLORS["first-party"], "align": "center"},
    )

    for cat in sorted(cat_domains.keys(), key=lambda c: (-cat_resource_total[c], c)):
        cid = _category_node_id(cat)
        n_dom = len(cat_domains[cat])
        tot = cat_resource_total[cat]
        ccolor = CATEGORY_COLORS.get(cat, CATEGORY_COLORS["unknown"])
        dom_word = "domain" if n_dom == 1 else "domains"
        cat_label = _category_display_name(cat)
        net.add_node(
            cid,
            label="\u200b",
            sxr_inner_count=tot,
            sxr_caption=cat_label,
            title=_plain_tip(
                cat_label,
                f"{n_dom} {dom_word} · {tot} resources",
            ),
            color=ccolor,
            size=_DIAMOND_NODE_SIZE,
            shape="diamond",
            font={"size": 1, "face": "Segoe UI, sans-serif", "color": ccolor, "align": "center"},
        )
        tr = "resource" if tot == 1 else "resources"
        net.add_edge(
            site,
            cid,
            value=tot,
            title=_plain_tip(f"{tot} {tr} → {_category_display_name(cat)}"),
            arrows="to",
        )

    seen_domain: set[str] = set()
    for dst, meta, primary_cat in domain_rows:
        cats = ", ".join(sorted(meta["categories"]))
        provs = ", ".join(sorted(meta["providers"])) if meta["providers"] else "(no provider label)"
        tag_lines = ", ".join(f"{t} ({c})" for t, c in sorted(meta["tags"].items(), key=lambda x: -x[1])[:5])
        color = CATEGORY_COLORS.get(primary_cat, CATEGORY_COLORS["unknown"])
        n = meta["count"]
        leaf_dot_size = 16

        tip = _plain_tip(
            dst,
            f"Categories: {cats}",
            f"Provider: {provs}",
            f"Resources: {meta['count']}",
            f"Tags: {tag_lines}" if tag_lines else "Tags: —",
        )
        if dst not in seen_domain:
            net.add_node(
                dst,
                label="\u200b",
                sxr_caption=dst,
                title=tip,
                color=color,
                size=leaf_dot_size,
                shape="dot",
                font={"size": 1, "face": "Segoe UI, sans-serif", "color": color, "align": "center"},
            )
            seen_domain.add(dst)

        cid = _category_node_id(primary_cat)
        rw = "resource" if n == 1 else "resources"
        edge_title = _plain_tip(f"{n} {rw}", f"Categories: {cats}")
        net.add_edge(
            cid,
            dst,
            value=n,
            title=edge_title,
            sxr_edge_label=str(n),
            arrows="to",
        )

    return _finalize_pyvis_html(net.generate_html())


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        raise SystemExit(f"Input not found: {args.input}")

    data = load_crawl(args.input)
    html = build_graph(data, width=args.width, height=args.height)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding="utf-8")
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes)")

    if not args.no_open:
        webbrowser.open(args.output.resolve().as_uri())
        print(f"Opened in default browser: {args.output.resolve().as_uri()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

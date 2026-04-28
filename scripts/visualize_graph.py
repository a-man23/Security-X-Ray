"""
Interactive third-party dependency graph from a Security X-Ray crawl JSON.

Writes HTML (PyVis) and opens it in your default web browser: fullscreen canvas,
initial top-down layout then free drag; hub (dot) + category diamonds + leaf dots show counts in canvas;
leaf size scales with total references; single-site graphs use a tree, multi-site (2+ crawled sites) use a radial layout; domain label under each node; diamond→leaf edges show counts and
scale in thickness; no corner navigation buttons.
"""

from __future__ import annotations

import argparse
import json
import webbrowser
from typing import Literal
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

_LEAF_NODE_SIZE_MIN = 16
_LEAF_NODE_SIZE_MAX = 44


def _leaf_node_size_from_total(tot: int) -> int:
    """Scale leaf dot diameter so totals fit inside (single- or multi-site)."""
    if tot < 1:
        return _LEAF_NODE_SIZE_MIN
    digits = len(str(int(tot)))
    # Smooth growth: small counts stay compact; hundreds/thousands get larger caps.
    base = _LEAF_NODE_SIZE_MIN + min(12, tot // 3) + (digits - 1) * 6
    return int(max(_LEAF_NODE_SIZE_MIN, min(_LEAF_NODE_SIZE_MAX, base)))


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


def _risk_reason_text(parts: list[str], max_items: int = 3) -> str:
    """Short, human-readable reason summary for hover cards."""
    cleaned = [p.strip() for p in parts if isinstance(p, str) and p.strip()]
    if not cleaned:
        return "No specific factors recorded."
    return " | ".join(cleaned[:max_items])


def _top_component_reasons(components: list[dict], max_items: int = 3) -> list[str]:
    """Extract top evidence strings from risk-score components."""
    reasons: list[str] = []
    for comp in components[:max_items]:
        ev = comp.get("evidence")
        if isinstance(ev, str) and ev.strip():
            reasons.append(ev.strip())
    return reasons


def _finalize_pyvis_html(
    html: str,
    *,
    post_layout: Literal["tree", "merged_radial"] = "tree",
) -> str:
    """Fill the browser tab: reset margins and stretch the network container.

    post_layout:
      tree — hierarchical layout, then unlock for drag (default for single-site crawls and multi-site
        when fewer than two crawled sites are present).
      merged_radial — radial layout when two or more site hubs exist: leaves on one inner circle
        by category angle, diamonds middle, hubs outer (radii scale with hub count). Used for aggregate
        bundles and combined crawls with 2+ sites.
    """
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

    # Hub + diamond counts (canvas); captions under nodes; custom hover risk card; then drop
    # hierarchical lock for free drag.
    hook = """
                  (function () {
                    var __sxrRel = false;
                    var __sxrTip = document.createElement("div");
                    __sxrTip.id = "sxr-risk-tooltip";
                    __sxrTip.style.position = "fixed";
                    __sxrTip.style.display = "none";
                    __sxrTip.style.pointerEvents = "none";
                    __sxrTip.style.background = "rgba(24,24,24,0.96)";
                    __sxrTip.style.border = "1px solid #3b3b3b";
                    __sxrTip.style.borderRadius = "8px";
                    __sxrTip.style.padding = "8px 10px";
                    __sxrTip.style.maxWidth = "360px";
                    __sxrTip.style.color = "#e6e6e6";
                    __sxrTip.style.font = "12px/1.35 Segoe UI, Arial, sans-serif";
                    __sxrTip.style.zIndex = "99999";
                    __sxrTip.style.boxShadow = "0 8px 24px rgba(0,0,0,0.45)";
                    document.body.appendChild(__sxrTip);

                    function __sxrClamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }
                    function __sxrRiskColor(score) {
                      var s = __sxrClamp(Number(score) || 0, 0, 100);
                      var hue = Math.round((100 - s) * 1.2); // 0->red, 100->green
                      return "hsl(" + hue + ", 88%, 52%)";
                    }
                    function __sxrEsc(v) {
                      return String(v)
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;");
                    }
                    function __sxrShowRiskTooltip(node, pointerDOM) {
                      if (!node) return;
                      var score = node.sxr_risk_score;
                      if (score === undefined || score === null) return;
                      var who = node.sxr_caption || node.id || "node";
                      var tier = String(node.sxr_risk_tier || "low").toUpperCase();
                      var reasons = String(node.sxr_risk_reason || "");
                      var scoreColor = __sxrRiskColor(score);
                      __sxrTip.innerHTML =
                        "<div style='font-weight:600;margin-bottom:4px;'>" + __sxrEsc(who) + "</div>" +
                        "<div style='margin-bottom:4px;'>Risk score: " +
                        "<span style='font-weight:700;color:" + scoreColor + ";'>" + __sxrEsc(score) + "/100</span>" +
                        " (" + __sxrEsc(tier) + ")" +
                        "</div>" +
                        "<div style='color:#cfcfcf;'>" + __sxrEsc(reasons || "No specific factors recorded.") + "</div>";
                      __sxrTip.style.display = "block";
                      var x = Math.round((pointerDOM && pointerDOM.x) ? pointerDOM.x : 0) + 14;
                      var y = Math.round((pointerDOM && pointerDOM.y) ? pointerDOM.y : 0) + 14;
                      __sxrTip.style.left = x + "px";
                      __sxrTip.style.top = y + "px";
                    }
                    function __sxrHideRiskTooltip() {
                      __sxrTip.style.display = "none";
                    }
                    network.on("hoverNode", function (params) {
                      try {
                        var n = nodes.get(params.node);
                        if (!n || !n.sxr_show_risk_hover) {
                          __sxrHideRiskTooltip();
                          return;
                        }
                        __sxrShowRiskTooltip(n, params.pointer && params.pointer.DOM);
                      } catch (e) { __sxrHideRiskTooltip(); }
                    });
                    network.on("blurNode", __sxrHideRiskTooltip);
                    network.on("dragStart", __sxrHideRiskTooltip);
                    network.on("zoom", __sxrHideRiskTooltip);
                    network.on("dragging", function (params) {
                      if (__sxrTip.style.display !== "block") return;
                      var hoverId = network.getNodeAt(params.pointer.DOM);
                      if (!hoverId) { __sxrHideRiskTooltip(); return; }
                      var n = nodes.get(hoverId);
                      if (!n || !n.sxr_show_risk_hover) { __sxrHideRiskTooltip(); return; }
                      __sxrShowRiskTooltip(n, params.pointer.DOM);
                    });
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
                              __SXR_POST_LAYOUT__
                            } catch (e2) {}
                          }, 80);
                        }
                      } catch (e) {}
                    });
                  })();
"""
    if post_layout == "merged_radial":
        post_js = r"""
                              (function mergedRadialLayout() {
                                var all = nodes.get();
                                var hubIds = [];
                                for (var hi = 0; hi < all.length; hi++) {
                                  if (all[hi].sxr_is_site_hub === true) hubIds.push(all[hi].id);
                                }
                                hubIds.sort();
                                if (hubIds.length === 0) return;
                                var pos0 = network.getPositions(hubIds);
                                var ax = 0, ay = 0, nn = 0;
                                for (var a0 = 0; a0 < hubIds.length; a0++) {
                                  var p0 = pos0[hubIds[a0]];
                                  if (!p0) continue;
                                  ax += p0.x; ay += p0.y; nn++;
                                }
                                if (nn) {
                                  ax /= nn; ay /= nn;
                                } else {
                                  ax = 0; ay = 0;
                                }
                                var ns = hubIds.length;
                                /* Radial layout: inner leaf ring, category diamonds, site hubs on outer ring. */
                                var R_in0 = 150 + ns * 24;
                                var eds = edges.get();
                                var catAngle = {};
                                for (var j2 = 0; j2 < ns; j2++) {
                                  var baseAng = -Math.PI / 2 + (2 * Math.PI * j2) / ns;
                                  var childIds = [];
                                  for (var e0 = 0; e0 < eds.length; e0++) {
                                    if (eds[e0].from === hubIds[j2]) {
                                      if (String(eds[e0].to).indexOf("__sxr_cat__") === 0) {
                                        childIds.push(eds[e0].to);
                                      }
                                    }
                                  }
                                  childIds.sort();
                                  var m = childIds.length;
                                  if (m === 0) continue;
                                  var maxW = (2 * Math.PI) / Math.max(ns, 2) * 0.78;
                                  var sp = Math.min(Math.PI * 0.45, maxW);
                                  for (var c = 0; c < m; c++) {
                                    var a2 = m === 1 ? baseAng : (baseAng - sp / 2 + (sp * c) / Math.max(1, m - 1));
                                    catAngle[childIds[c]] = a2;
                                  }
                                }
                                var leafIds = [];
                                for (var t = 0; t < all.length; t++) {
                                  var tid = all[t].id;
                                  if (all[t].sxr_is_site_hub === true) continue;
                                  if (String(tid).indexOf("__sxr_cat__") === 0) continue;
                                  leafIds.push(tid);
                                }
                                function edgeWeight(ed) {
                                  var w = ed.value;
                                  if (typeof w === "number" && !isNaN(w)) return w;
                                  var lab = ed.sxr_edge_label;
                                  if (lab === undefined || lab === null) return 0;
                                  var p = parseFloat(String(lab));
                                  return isNaN(p) ? 0 : p;
                                }
                                function leafDia(id) {
                                  try {
                                    var nd = nodes.get(id);
                                    if (nd && typeof nd.size === "number") return nd.size;
                                  } catch (eD) {}
                                  return 16;
                                }
                                function effLeafR(dia) {
                                  return dia * 0.5 + 22;
                                }
                                var bucket = {};
                                for (var li = 0; li < leafIds.length; li++) {
                                  var lid = leafIds[li];
                                  var bestFr = null;
                                  var bestW = -1;
                                  for (var e1 = 0; e1 < eds.length; e1++) {
                                    if (eds[e1].to !== lid) continue;
                                    var fr = eds[e1].from;
                                    if (String(fr).indexOf("__sxr_cat__") !== 0) continue;
                                    var w = edgeWeight(eds[e1]);
                                    if (w > bestW || (w === bestW && (bestFr === null || String(fr) < String(bestFr)))) {
                                      bestW = w;
                                      bestFr = fr;
                                    }
                                  }
                                  if (bestFr === null) continue;
                                  var ca0 = catAngle[bestFr];
                                  if (ca0 === undefined) continue;
                                  if (!bucket[bestFr]) bucket[bestFr] = [];
                                  bucket[bestFr].push({ id: lid, dia: leafDia(lid), ew: bestW });
                                }
                                var sectors = [];
                                for (var bki in bucket) {
                                  if (!bucket.hasOwnProperty(bki)) continue;
                                  var caB = catAngle[bki];
                                  if (caB === undefined) continue;
                                  var arr = bucket[bki].slice();
                                  arr.sort(function (a, b) {
                                    if (b.ew !== a.ew) return b.ew - a.ew;
                                    var sa = String(a.id);
                                    var sb = String(b.id);
                                    return sa < sb ? -1 : sa > sb ? 1 : 0;
                                  });
                                  sectors.push({ catId: bki, ca: caB, leaves: arr });
                                }
                                sectors.sort(function (a, b) {
                                  if (a.ca !== b.ca) return a.ca - b.ca;
                                  return String(a.catId) < String(b.catId) ? -1 : 1;
                                });
                                var siteScale = ns < 2 ? 1.0 : 1.0 + (ns - 2) * 0.14;
                                var pad = 20 * siteScale;
                                var maxD = 16;
                                for (var sx = 0; sx < sectors.length; sx++) {
                                  var Ls = sectors[sx].leaves;
                                  for (var sy = 0; sy < Ls.length; sy++) {
                                    if (Ls[sy].dia > maxD) maxD = Ls[sy].dia;
                                  }
                                }
                                function bucketAngularWidth(R, leaves) {
                                  var n = leaves.length;
                                  if (n === 0) return 0;
                                  if (R < 2) R = 2;
                                  if (n === 1) {
                                    var er1 = effLeafR(leaves[0].dia);
                                    return Math.max(0.11, 2 * Math.asin(Math.min(0.999, er1 / R)));
                                  }
                                  var step = 0;
                                  for (var ii = 0; ii < n - 1; ii++) {
                                    var need =
                                      effLeafR(leaves[ii].dia) +
                                      effLeafR(leaves[ii + 1].dia) +
                                      pad;
                                    var s = 2 * Math.asin(Math.min(0.999, need / (2 * R)));
                                    if (s > step) step = s;
                                  }
                                  return (n - 1) * step;
                                }
                                function gapBetweenBuckets(R) {
                                  var need = effLeafR(maxD) + effLeafR(maxD) + pad;
                                  return Math.max(0.052, 2 * Math.asin(Math.min(0.999, need / (2 * R))));
                                }
                                function totalAngularNeed(R) {
                                  if (sectors.length === 0) return 0;
                                  var g = gapBetweenBuckets(R);
                                  var tot = g * sectors.length;
                                  for (var bi = 0; bi < sectors.length; bi++) {
                                    tot += bucketAngularWidth(R, sectors[bi].leaves);
                                  }
                                  return tot;
                                }
                                var R_leaf = R_in0;
                                if (sectors.length > 0) {
                                  var hi = R_in0 * 2;
                                  while (totalAngularNeed(hi) > 2 * Math.PI && hi < R_in0 * 80) {
                                    hi *= 1.4;
                                  }
                                  var lo = R_in0;
                                  for (var it = 0; it < 28; it++) {
                                    var mid = (lo + hi) * 0.5;
                                    if (totalAngularNeed(mid) <= 2 * Math.PI) hi = mid;
                                    else lo = mid;
                                  }
                                  R_leaf = hi;
                                  if (totalAngularNeed(R_leaf) > 2 * Math.PI) R_leaf = hi * 1.25;
                                }
                                function angularOccupied(R) {
                                  if (sectors.length === 0) return 0;
                                  var g = gapBetweenBuckets(R);
                                  var prev = null;
                                  var first = null;
                                  for (var z = 0; z < sectors.length; z++) {
                                    var sec2 = sectors[z];
                                    var wz = bucketAngularWidth(R, sec2.leaves);
                                    var idl = sec2.ca - wz * 0.5;
                                    var st = prev === null ? idl : Math.max(prev + g, idl);
                                    if (first === null) first = st;
                                    prev = st + wz;
                                  }
                                  return prev - first;
                                }
                                while (
                                  sectors.length > 0 &&
                                  angularOccupied(R_leaf) > 2 * Math.PI * 1.02 &&
                                  R_leaf < R_in0 * 100
                                ) {
                                  R_leaf *= 1.22;
                                }
                                /* Diamonds outside leaves: enforce a visible min gap (world px) so cat→leaf edges read long. */
                                var MIN_DIAMOND_LEAF_CENTER = 96;
                                var leafInwardNudge = Math.min(88, Math.max(28, R_leaf * 0.17));
                                var R_leafDraw = Math.max(R_in0 * 0.48, R_leaf - leafInwardNudge);
                                var baseMid = R_leaf + 22 + maxD * 0.5 + pad + 20;
                                var R_mid = Math.max(
                                  R_in0 + 110,
                                  baseMid,
                                  R_leafDraw + MIN_DIAMOND_LEAF_CENTER
                                );
                                var R_out = R_mid + 100;
                                for (var j = 0; j < ns; j++) {
                                  var ang0 = -Math.PI / 2 + (2 * Math.PI * j) / ns;
                                  network.moveNode(
                                    hubIds[j],
                                    ax + R_out * Math.cos(ang0),
                                    ay + R_out * Math.sin(ang0)
                                  );
                                }
                                for (var j3 = 0; j3 < ns; j3++) {
                                  var baseAng2 = -Math.PI / 2 + (2 * Math.PI * j3) / ns;
                                  var childIds2 = [];
                                  for (var e2 = 0; e2 < eds.length; e2++) {
                                    if (eds[e2].from === hubIds[j3]) {
                                      if (String(eds[e2].to).indexOf("__sxr_cat__") === 0) {
                                        childIds2.push(eds[e2].to);
                                      }
                                    }
                                  }
                                  childIds2.sort();
                                  var m2 = childIds2.length;
                                  if (m2 === 0) continue;
                                  var maxW2 = (2 * Math.PI) / Math.max(ns, 2) * 0.78;
                                  var sp2 = Math.min(Math.PI * 0.45, maxW2);
                                  for (var c2 = 0; c2 < m2; c2++) {
                                    var a3 = m2 === 1 ? baseAng2 : (baseAng2 - sp2 / 2 + (sp2 * c2) / Math.max(1, m2 - 1));
                                    var cid2 = childIds2[c2];
                                    network.moveNode(
                                      cid2,
                                      ax + R_mid * Math.cos(a3),
                                      ay + R_mid * Math.sin(a3)
                                    );
                                  }
                                }
                                var gUse = sectors.length > 0 ? gapBetweenBuckets(R_leaf) : 0;
                                var prevEnd = null;
                                for (var sb = 0; sb < sectors.length; sb++) {
                                  var sec = sectors[sb];
                                  var leaves = sec.leaves;
                                  var wb = bucketAngularWidth(R_leaf, leaves);
                                  var idealStart = sec.ca - wb * 0.5;
                                  var start =
                                    prevEnd === null ? idealStart : Math.max(prevEnd + gUse, idealStart);
                                  var nsub = leaves.length;
                                  for (var ii = 0; ii < nsub; ii++) {
                                    var angL =
                                      nsub === 1 ? start + wb * 0.5 : start + (wb * ii) / Math.max(1, nsub - 1);
                                    var node = leaves[ii];
                                    network.moveNode(
                                      node.id,
                                      ax + R_leafDraw * Math.cos(angL),
                                      ay + R_leafDraw * Math.sin(angL)
                                    );
                                  }
                                  prevEnd = start + wb;
                                }
                                try {
                                  network.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
                                } catch (fitE) {}
                              })();
"""
    else:
        post_js = ""

    hook = hook.replace("__SXR_POST_LAYOUT__", post_js)

    marker = "network = new vis.Network(container, data, options);"
    if marker in html:
        html = html.replace(marker, marker + hook, 1)
    return html


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Visualize crawl output as an interactive domain graph in the browser.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input",
        "-i",
        type=Path,
        help=(
            "Per-site crawl JSON, output/_aggregate.json (summary), or "
            "output/aggregate_graph.json (full crawl bundle for graphing without re-crawl)."
        ),
    )
    group.add_argument(
        "--inputs",
        nargs="+",
        type=Path,
        help="One or more per-site crawl JSON files to build a combined multi-site graph.",
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


def load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"Not a valid JSON object: {path}")
    return data


def _vis_options_block() -> str:
    return """
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


def build_aggregate_graph(data: dict, width: int | None, height: int | None) -> str:
    """
    Graph from output/_aggregate.json: site hub -> category diamonds only
    (no third-party domain leaves; aggregate file has no per-domain rows).
    """
    per_site = data.get("per_site")
    if not isinstance(per_site, list):
        raise SystemExit("Aggregate JSON missing per_site array")

    wstr = f"{width}px" if width is not None else "100vw"
    hstr = f"{height}px" if height is not None else "100vh"

    net = Network(
        height=hstr,
        width=wstr,
        bgcolor="#1e1e1e",
        font_color="#e0e0e0",
        directed=True,
    )
    net.set_options(_vis_options_block())

    # Stable site order: most third-party first
    rows = sorted(
        per_site,
        key=lambda r: (-int(r.get("third_party_count") or 0), str(r.get("site_domain") or "")),
    )
    site_risk_map = {
        str(r.get("site_domain")): (r.get("risk_score") or {})
        for r in rows
        if r.get("site_domain")
    }

    for row in rows:
        site = row.get("site_domain")
        if not site:
            continue
        tot = int(row.get("third_party_count") or 0)
        res_word = "third-party resource" if tot == 1 else "third-party resources"
        site_risk = site_risk_map.get(site, {})
        site_risk_components = site_risk.get("components") if isinstance(site_risk, dict) else []
        site_risk_reasons = _top_component_reasons(site_risk_components if isinstance(site_risk_components, list) else [])
        net.add_node(
            site,
            label="\u200b",
            sxr_inner_count=tot,
            sxr_caption=site,
            sxr_is_site_hub=True,
            sxr_show_risk_hover=True,
            sxr_risk_score=int(site_risk.get("score", 0)) if isinstance(site_risk, dict) else 0,
            sxr_risk_tier=str(site_risk.get("tier", "low")) if isinstance(site_risk, dict) else "low",
            sxr_risk_reason=_risk_reason_text(
                site_risk_reasons + [f"{tot} {res_word}", str(row.get("target_url") or "")]
            ),
            title=None,
            color=CATEGORY_COLORS["first-party"],
            size=_HUB_NODE_SIZE,
            shape="dot",
            font={"size": 1, "face": "Segoe UI, sans-serif", "color": CATEGORY_COLORS["first-party"], "align": "center"},
        )

        by_cat = row.get("by_category") or {}
        if not isinstance(by_cat, dict):
            continue
        for cat, raw_n in sorted(by_cat.items(), key=lambda x: (-int(x[1] or 0), x[0])):
            n = int(raw_n or 0)
            if n <= 0:
                continue
            cid = f"{_category_node_id(cat)}__{site}"
            ccolor = CATEGORY_COLORS.get(cat, CATEGORY_COLORS["unknown"])
            cat_label = _category_display_name(cat)
            net.add_node(
                cid,
                label="\u200b",
                sxr_inner_count=n,
                sxr_caption=cat_label,
                title=_plain_tip(cat_label, f"Site: {site}", f"{n} resources (aggregate by category)"),
                color=ccolor,
                size=_DIAMOND_NODE_SIZE,
                shape="diamond",
                font={"size": 1, "face": "Segoe UI, sans-serif", "color": ccolor, "align": "center"},
            )
            tr = "resource" if n == 1 else "resources"
            net.add_edge(
                site,
                cid,
                value=n,
                title=_plain_tip(f"{n} {tr} -> {cat_label}", f"Site: {site}"),
                arrows="to",
            )

    sites_in_graph = {row.get("site_domain") for row in rows if row.get("site_domain")}
    layout = "merged_radial" if len(sites_in_graph) >= 2 else "tree"
    return _finalize_pyvis_html(net.generate_html(), post_layout=layout)


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
    net.set_options(_vis_options_block())

    # Per third-party domain: primary category + full edge metadata (one row per domain).
    domain_rows: list[tuple[str, dict, str]] = []
    for (src, dst), meta in edge_meta.items():
        assert src == site
        primary_cat = sorted(meta["categories"], key=lambda c: (c != "unknown", c))[0]
        domain_rows.append((dst, meta, primary_cat))

    domain_rows.sort(key=lambda x: (-x[1]["count"], x[2], x[0]))

    domain_totals_single: dict[str, int] = defaultdict(int)
    for dst, meta, _pc in domain_rows:
        domain_totals_single[dst] += meta["count"]
    domain_risk_map: dict[str, dict] = {}
    for row in data.get("summary", {}).get("domain_risk_scores", []):
        domain = row.get("domain")
        if isinstance(domain, str):
            domain_risk_map[domain] = row
    site_risk = data.get("summary", {}).get("risk_score", {})
    site_risk_reasons = _top_component_reasons(site_risk.get("components", [])) if isinstance(site_risk, dict) else []

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
        sxr_show_risk_hover=True,
        sxr_risk_score=int(site_risk.get("score", 0)) if isinstance(site_risk, dict) else 0,
        sxr_risk_tier=str(site_risk.get("tier", "low")) if isinstance(site_risk, dict) else "low",
        sxr_risk_reason=_risk_reason_text(site_risk_reasons + [f"{grand_total} {res_word} (sum of edges below)"]),
        title=None,
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
        leaf_total = domain_totals_single[dst]
        leaf_sz = _leaf_node_size_from_total(leaf_total)

        domain_risk = domain_risk_map.get(dst, {})
        domain_risk_reasons = _top_component_reasons(domain_risk.get("components", [])) if isinstance(domain_risk, dict) else []
        if not domain_risk_reasons:
            domain_risk_reasons = [
                f"{meta['count']} resources from this site",
                f"{len(meta['tags'])} resource tag types",
            ]
        if dst not in seen_domain:
            net.add_node(
                dst,
                label="\u200b",
                sxr_inner_count=leaf_total,
                sxr_caption=dst,
                sxr_show_risk_hover=True,
                sxr_risk_score=int(domain_risk.get("score", 0)) if isinstance(domain_risk, dict) else 0,
                sxr_risk_tier=str(domain_risk.get("tier", "low")) if isinstance(domain_risk, dict) else "low",
                sxr_risk_reason=_risk_reason_text(domain_risk_reasons),
                title=None,
                color=color,
                size=leaf_sz,
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


def build_multi_site_graph(results: list[dict], width: int | None, height: int | None) -> str:
    wstr = f"{width}px" if width is not None else "100vw"
    hstr = f"{height}px" if height is not None else "100vh"

    # Per-site domain metadata (site -> domain), mirroring single-site logic.
    edge_meta: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"count": 0, "tags": defaultdict(int), "providers": set(), "categories": set()}
    )
    site_totals: dict[str, int] = defaultdict(int)
    domain_category_votes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    site_risk_map: dict[str, dict] = {}
    domain_risk_rollup: dict[str, dict] = defaultdict(
        lambda: {"scores": [], "tiers": [], "reasons": []}
    )

    for data in results:
        site = data.get("crawl_metadata", {}).get("site_domain")
        if not site:
            continue
        site_risk = data.get("summary", {}).get("risk_score", {})
        if isinstance(site_risk, dict):
            site_risk_map[site] = site_risk
        for drow in data.get("summary", {}).get("domain_risk_scores", []):
            domain = drow.get("domain")
            if not isinstance(domain, str):
                continue
            agg = domain_risk_rollup[domain]
            agg["scores"].append(int(drow.get("score", 0)))
            agg["tiers"].append(str(drow.get("tier", "low")))
            if isinstance(drow.get("components"), list):
                agg["reasons"].extend(_top_component_reasons(drow["components"], max_items=2))
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
            cat = res.get("category", "unknown")
            edge_meta[key]["categories"].add(cat)
            site_totals[site] += 1
            domain_category_votes[d][cat] += 1

    domain_grand_totals: dict[str, int] = defaultdict(int)
    for (_site, dst), meta in edge_meta.items():
        domain_grand_totals[dst] += meta["count"]

    net = Network(
        height=hstr,
        width=wstr,
        bgcolor="#1e1e1e",
        font_color="#e0e0e0",
        directed=True,
    )
    net.set_options(_vis_options_block())

    # Build per-site category hubs like the single-site graph.
    # Key: (site, category) -> domains/total for that site-category branch.
    site_cat_domains: dict[tuple[str, str], list[tuple[str, dict]]] = defaultdict(list)
    site_cat_totals: dict[tuple[str, str], int] = defaultdict(int)
    domain_rows = sorted(edge_meta.items(), key=lambda item: (-item[1]["count"], item[0][0], item[0][1]))
    for (site, dst), meta in domain_rows:
        primary_cat = sorted(meta["categories"], key=lambda c: (c != "unknown", c))[0]
        key = (site, primary_cat)
        site_cat_domains[key].append((dst, meta))
        site_cat_totals[key] += meta["count"]

    # One hub node per crawled site (same style as single-site crawl hub).
    for site in sorted(site_totals.keys(), key=lambda s: (-site_totals[s], s)):
        tot = site_totals[site]
        res_word = "third-party resource" if tot == 1 else "third-party resources"
        site_risk = site_risk_map.get(site, {})
        site_reasons = _top_component_reasons(site_risk.get("components", [])) if isinstance(site_risk, dict) else []
        net.add_node(
            site,
            label="\u200b",
            sxr_inner_count=tot,
            sxr_caption=site,
            sxr_is_site_hub=True,
            sxr_show_risk_hover=True,
            sxr_risk_score=int(site_risk.get("score", 0)) if isinstance(site_risk, dict) else 0,
            sxr_risk_tier=str(site_risk.get("tier", "low")) if isinstance(site_risk, dict) else "low",
            sxr_risk_reason=_risk_reason_text(site_reasons + [f"{tot} {res_word}"]),
            title=None,
            color=CATEGORY_COLORS["first-party"],
            size=_HUB_NODE_SIZE,
            shape="dot",
            font={"size": 1, "face": "Segoe UI, sans-serif", "color": CATEGORY_COLORS["first-party"], "align": "center"},
        )

    # Category diamonds per site (not global), so each site keeps its own category branch.
    for (site, cat), tot in sorted(site_cat_totals.items(), key=lambda item: (-item[1], item[0][0], item[0][1])):
        cid = f"{_category_node_id(cat)}__{site}"
        n_dom = len(site_cat_domains[(site, cat)])
        ccolor = CATEGORY_COLORS.get(cat, CATEGORY_COLORS["unknown"])
        dom_word = "domain" if n_dom == 1 else "domains"
        cat_label = _category_display_name(cat)
        net.add_node(
            cid,
            label="\u200b",
            sxr_inner_count=tot,
            sxr_caption=cat_label,
            title=_plain_tip(cat_label, f"{site}", f"{n_dom} {dom_word} · {tot} resources"),
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
            title=_plain_tip(f"{tot} {tr} -> {cat_label}", f"Site: {site}"),
            arrows="to",
        )

    seen_domain: set[str] = set()
    for (site, dst), meta in domain_rows:
        cats = ", ".join(sorted(meta["categories"]))
        provs = ", ".join(sorted(meta["providers"])) if meta["providers"] else "(no provider label)"
        tag_lines = ", ".join(f"{t} ({c})" for t, c in sorted(meta["tags"].items(), key=lambda x: -x[1])[:5])
        n = meta["count"]

        if dst not in seen_domain:
            vote_map = domain_category_votes.get(dst, {})
            primary_cat = sorted(vote_map.items(), key=lambda x: (-x[1], x[0]))[0][0] if vote_map else "unknown"
            color = CATEGORY_COLORS.get(primary_cat, CATEGORY_COLORS["unknown"])
            grand = domain_grand_totals[dst]
            leaf_sz = _leaf_node_size_from_total(grand)
            droll = domain_risk_rollup.get(dst, {"scores": [], "tiers": [], "reasons": []})
            dscores = droll.get("scores", [])
            avg_score = int(round(sum(dscores) / len(dscores))) if dscores else 0
            tier = "low"
            if avg_score >= 75:
                tier = "critical"
            elif avg_score >= 50:
                tier = "high"
            elif avg_score >= 25:
                tier = "medium"
            reasons = droll.get("reasons", [])
            net.add_node(
                dst,
                label="\u200b",
                sxr_inner_count=grand,
                sxr_caption=dst,
                sxr_show_risk_hover=True,
                sxr_risk_score=avg_score,
                sxr_risk_tier=tier,
                sxr_risk_reason=_risk_reason_text(reasons if reasons else [f"{grand} resources across crawled sites"]),
                title=None,
                color=color,
                size=leaf_sz,
                shape="dot",
                font={"size": 1, "face": "Segoe UI, sans-serif", "color": color, "align": "center"},
            )
            seen_domain.add(dst)

        primary_cat = sorted(meta["categories"], key=lambda c: (c != "unknown", c))[0]
        cid = f"{_category_node_id(primary_cat)}__{site}"
        rw = "resource" if n == 1 else "resources"
        edge_title = _plain_tip(
            f"{site} -> {dst}",
            f"{n} {rw}",
            f"Categories: {cats}",
            f"Provider: {provs}",
            f"Tags: {tag_lines}" if tag_lines else "Tags: —",
        )
        net.add_edge(
            cid,
            dst,
            value=n,
            title=edge_title,
            sxr_edge_label=str(n),
            arrows="to",
        )

    crawled_sites = set()
    for d in results:
        sd = d.get("crawl_metadata", {}).get("site_domain")
        if sd:
            crawled_sites.add(sd)
    layout = "merged_radial" if len(crawled_sites) >= 2 else "tree"
    return _finalize_pyvis_html(net.generate_html(), post_layout=layout)


def main() -> int:
    args = parse_args()
    if args.input:
        if not args.input.exists():
            raise SystemExit(f"Input not found: {args.input}")
        blob = load_json(args.input)
        if blob.get("report_type") == "aggregate_graph" and isinstance(blob.get("crawl_results"), list):
            html = build_multi_site_graph(blob["crawl_results"], width=args.width, height=args.height)
        elif blob.get("report_type") == "aggregate" and isinstance(blob.get("per_site"), list):
            html = build_aggregate_graph(blob, width=args.width, height=args.height)
        elif "crawl_metadata" in blob:
            html = build_graph(blob, width=args.width, height=args.height)
        else:
            raise SystemExit(
                f"Unsupported JSON for --input: {args.input} "
                "(per-site crawl *.json, _aggregate.json, or aggregate_graph.json)"
            )
    else:
        paths = args.inputs or []
        if not paths:
            raise SystemExit("No --inputs provided.")
        missing = [p for p in paths if not p.exists()]
        if missing:
            raise SystemExit(f"Input not found: {missing[0]}")
        results = [load_crawl(p) for p in paths]
        html = build_multi_site_graph(results, width=args.width, height=args.height)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding="utf-8")
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes)")

    if not args.no_open:
        webbrowser.open(args.output.resolve().as_uri())
        print(f"Opened in default browser: {args.output.resolve().as_uri()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

// Pathology web UI: no dependencies, no external requests, no innerHTML.
"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);

function el(tag, attrs, text) {
  const e = tag === "svg" || ["g", "rect", "text", "path", "title"].includes(tag)
    ? document.createElementNS(SVG_NS, tag)
    : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  if (text !== undefined) e.textContent = String(text);
  return e;
}

async function api(path) {
  const headers = {};
  const token = $("token").value.trim();
  if (token) headers.Authorization = "Bearer " + token;
  const resp = await fetch(path, { headers, cache: "no-store" });
  let body = null;
  try { body = await resp.json(); } catch (_) { /* non-JSON error */ }
  if (!resp.ok) throw new Error((body && body.error) || ("HTTP " + resp.status));
  return body;
}

function collapse(path) {
  const out = [];
  for (const a of path) if (out[out.length - 1] !== a) out.push(a);
  return out;
}

// Columns by distance from the origin; edges between consecutive hops.
function drawGraph(paths) {
  const box = $("graph");
  box.replaceChildren();
  if (!paths.length) {
    box.append(el("p", { class: "hint" }, "No current paths for this prefix."));
    return;
  }
  const level = new Map();
  const edges = new Set();
  let depth = 0;
  for (const p of paths) {
    const hops = collapse(p.as_path);
    hops.forEach((asn, i) => {
      const d = hops.length - 1 - i;
      level.set(asn, Math.max(level.get(asn) ?? 0, d));
      depth = Math.max(depth, d);
      if (i > 0) edges.add(hops[i - 1] + ">" + asn);
    });
  }
  const columns = [];
  for (const [asn, d] of level) (columns[d] ||= []).push(asn);
  columns.forEach((c) => c && c.sort((a, b) => a - b));
  const W = 120, H = 44, NW = 96, NH = 26, PAD = 16;
  const rows = Math.max(...columns.map((c) => (c ? c.length : 0)));
  const width = PAD * 2 + (depth + 1) * W;
  const height = PAD * 2 + rows * H;
  const pos = new Map();
  columns.forEach((c, d) => (c || []).forEach((asn, r) => {
    pos.set(asn, { x: PAD + (depth - d) * W, y: PAD + r * H + (rows - c.length) * H / 2 });
  }));
  const svg = el("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "AS path graph" });
  for (const e of edges) {
    const [from, to] = e.split(">").map(Number);
    const a = pos.get(from), b = pos.get(to);
    if (!a || !b) continue;
    const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2;
    svg.append(el("path", { class: "edge", d: `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}` }));
  }
  for (const [asn, p] of pos) {
    const g = el("g", { class: "node" + (level.get(asn) === 0 ? " origin" : "") });
    g.append(el("title", {}, "AS" + asn));
    g.append(el("rect", { x: p.x, y: p.y, width: NW, height: NH, rx: 5 }));
    g.append(el("text", { x: p.x + NW / 2, y: p.y + NH / 2 + 4, "text-anchor": "middle" }, "AS" + asn));
    svg.append(g);
  }
  box.append(svg);
}

function fillTable(id, rows) {
  const body = $(id).querySelector("tbody");
  body.replaceChildren();
  for (const cells of rows) {
    const tr = el("tr");
    for (const [text, cls] of cells) tr.append(el("td", cls ? { class: cls } : {}, text));
    body.append(tr);
  }
}

async function show(prefix) {
  const status = $("status");
  status.textContent = "Loading " + prefix + "...";
  try {
    const enc = encodeURIComponent(prefix);
    const [paths, events] = await Promise.all([
      api("/v1/prefixes/" + enc + "/paths"),
      api("/v1/routes?limit=200&prefix=" + enc),
    ]);
    drawGraph(paths.paths);
    fillTable("paths", paths.paths.map((p) => [
      [p.router], [p.peer], ["AS" + p.peer_asn], [p.as_path.join(" "), "mono"],
      [p.origin == null ? "-" : "AS" + p.origin], [p.since],
    ]));
    fillTable("events", events.events.slice().reverse().map((e) => [
      [e.time], [e.kind, e.kind === "withdraw" ? "withdraw" : ""], [e.prefix],
      [e.peer + " (AS" + e.peer_asn + ")"], [e.as_path.join(" "), "mono"],
      [e.communities.concat(e.large_communities).join(" "), "mono"],
    ]));
    status.textContent = paths.paths.length + " current paths, " + events.events.length + " events.";
    history.replaceState(null, "", "#" + prefix);
  } catch (err) {
    status.textContent = "Error: " + err.message;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("query").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const p = $("prefix").value.trim();
    if (p) show(p);
  });
  const initial = decodeURIComponent(location.hash.slice(1));
  if (/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(initial)) {
    $("prefix").value = initial;
    show(initial);
  }
});

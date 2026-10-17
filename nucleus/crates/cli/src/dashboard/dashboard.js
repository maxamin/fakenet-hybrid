// The FakeNet live dashboard. Every value shown comes from the sample under analysis, so
// everything is rendered with textContent: never as HTML.
"use strict";

const state = { after: 0, records: [], kinds: new Set(), dns: new Map(), http: new Map(), credentials: new Map(), protocols: new Map() };
const MAX_ROWS = 500;
const $ = (id) => document.getElementById(id);

function text(value) {
  if (value === null || value === undefined) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function element(tag, content, className) {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}

function tally(map, key) {
  if (key) map.set(key, (map.get(key) || 0) + 1);
}

function renderList(id, map, limit = 200) {
  const list = $(id);
  list.replaceChildren(...[...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([key, count]) => element("li", count > 1 ? `${key}  ×${count}` : key)));
}

const COMMON = new Set(["timestamp", "kind", "listener", "protocol", "transport", "tls", "src", "dst", "process", "session_id"]);

function details(record) {
  return Object.entries(record).filter(([k]) => !COMMON.has(k)).map(([k, v]) => `${k}=${text(v)}`).join("  ").slice(0, 600);
}

function visible(record) {
  const kind = $("kind").value;
  const search = $("search").value.toLowerCase();
  return (!kind || record.kind === kind) && (!search || JSON.stringify(record).toLowerCase().includes(search));
}

function row(record) {
  const tr = document.createElement("tr");
  const process = record.process ? `${text(record.process.name)} (${text(record.process.pid)})` : "";
  const time = text(record.timestamp).slice(11, 19);
  tr.append(element("td", time), element("td", text(record.kind)), element("td", text(record.protocol)),
    element("td", record.src ? `${text(record.src)} → ${text(record.dst)}` : ""), element("td", process), element("td", details(record), "details"));
  return tr;
}

function renderRecords() {
  if ($("pause").checked) return;
  const rows = state.records.filter(visible).slice(-MAX_ROWS).reverse().map(row);
  $("records").replaceChildren(...rows);
}

function absorb(record) {
  state.records.push(record);
  if (state.records.length > 5000) state.records.splice(0, state.records.length - 5000);
  if (!state.kinds.has(record.kind)) {
    state.kinds.add(record.kind);
    $("kind").append(element("option", text(record.kind)));
  }
  const meta = record.meta || {};
  if (record.kind === "event") {
    tally(state.protocols, text(record.protocol));
    if (record.protocol === "dns") tally(state.dns, `${text(meta.qname)} (${text(meta.qtype)})`);
    if (record.protocol === "http") tally(state.http, `${text(meta.method)} ${text(meta.host)}${text(meta.path)}`);
  }
  if (record.kind === "credentials") tally(state.credentials, `${text(record.protocol)}: ${text(record.username)} / ${text(record.password)}`);
}

async function poll() {
  try {
    const response = await fetch(`/api/records?after=${state.after}&limit=1000`, { credentials: "same-origin" });
    if (response.ok) {
      const body = await response.json();
      for (const entry of body.records) {
        absorb(entry.record);
        state.after = entry.seq;
      }
      renderList("dns", state.dns);
      renderList("http", state.http);
      renderList("credentials", state.credentials);
      renderList("protocols", state.protocols);
      renderRecords();
    }
  } catch (e) {
    $("link").textContent = "nucleus unreachable";
    $("link").className = "pill bad";
  }
}

async function summary() {
  try {
    const response = await fetch("/api/summary", { credentials: "same-origin" });
    if (!response.ok) return;
    const s = await response.json();
    const d = s.daemon || {};
    $("link").textContent = d.websocket_connected ? "daemon connected" : d.websocket_configured || d.http_configured ? "daemon unavailable: defaults" : "no daemon: defaults";
    $("link").className = d.websocket_connected ? "pill ok" : "pill bad";
    $("counters").textContent = `decisions ${text(d.decisions)} · fallbacks ${text(d.fallbacks)} · reconnects ${text(d.reconnects)} · records ${state.after}`;
    $("listeners").replaceChildren(...(s.listeners || []).map((l) => element("li", `${text(l.name)}: ${text(l.transport)} ${text(l.address)}`)));
    const e = s.explorer;
    if (e) {
      $("explorer").textContent = `${text(e.proposals)} answers · ${text(e.behaviors)} kinds of behaviour · functions ${text(e.functions_reached)} of ${text(e.functions_known)}`;
      $("explorer-templates").replaceChildren(...(e.templates || []).map((t) => element("li", `${text(t.template)}: reward ${text(t.reward)} → ${(t.functions || []).map(text).join(", ") || "behaviour"}`)));
    }
  } catch (e) { /* poll() reports reachability */ }
}

$("kind").addEventListener("change", renderRecords);
$("search").addEventListener("input", renderRecords);
$("pause").addEventListener("change", renderRecords);
poll();
summary();
setInterval(poll, 1000);
setInterval(summary, 2000);

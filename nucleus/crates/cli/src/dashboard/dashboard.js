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
    const l = s.limits || {};
    const refused = (l.refused_max_sessions || 0) + (l.refused_rate || 0) + (l.refused_memory || 0);
    $("counters").textContent = `decisions ${text(d.decisions)} · fallbacks ${text(d.fallbacks)} · reconnects ${text(d.reconnects)} · records ${state.after}`
      + ` · sessions ${text(l.sessions_active ?? "?")}` + (refused ? ` · refused by limits ${refused} (sessions ${text(l.refused_max_sessions)}, rate ${text(l.refused_rate)}, memory ${text(l.refused_memory)})` : "");
    $("listeners").replaceChildren(...(s.listeners || []).map((l) => element("li", `${text(l.name)}: ${text(l.transport)} ${text(l.address)}`)));
    const e = s.explorer;
    if (e) {
      $("explorer").textContent = `${text(e.proposals)} answers · ${text(e.behaviors)} kinds of behaviour · functions ${text(e.functions_reached)} of ${text(e.functions_known)}`;
      $("explorer-templates").replaceChildren(...(e.templates || []).map((t) => element("li", `${text(t.template)}: reward ${text(t.reward)} → ${(t.functions || []).map(text).join(", ") || "behaviour"}`)));
    }
  } catch (e) { /* poll() reports reachability */ }
}

// Live manual mode: requests held until the analyst answers (or they time out)
const held = new Map();

function fromBase64(encoded) {
  const binary = atob(encoded || "");
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function asText(bytes) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (e) { return null; }
}

function preview(bytes) {
  // Control characters shown as \xNN, so nothing invisible hides in the request
  let out = "";
  for (const b of bytes.slice(0, 4096)) out += b === 10 ? "\n" : b === 13 ? "\\r" : b === 9 ? "\t" : b < 32 || b > 126 ? `\\x${b.toString(16).padStart(2, "0")}` : String.fromCharCode(b);
  return bytes.length > 4096 ? `${out}\n… ${bytes.length - 4096} more bytes` : out;
}

async function answer(id, body, card) {
  card.querySelectorAll("button").forEach((b) => { b.disabled = true; });
  try {
    const response = await fetch(`/api/manual/${id}`, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) card.querySelector(".status").textContent = `not sent: ${(await response.json()).error}`;
  } catch (e) {
    card.querySelector(".status").textContent = "not sent: nucleus unreachable";
  }
}

function heldCard(item) {
  const card = element("article", "", "held");
  const process = item.process ? ` · ${text(item.process.name)} (${text(item.process.pid)})` : "";
  card.append(element("div", `${text(item.protocol)}${item.tls ? "+tls" : ""} ${text(item.src)} → ${text(item.dst)}${process}`, "muted"));
  card.append(element("div", `${text(item.host)} ${text(item.request)}`.trim() || "(no request line)", "request"));
  card.append(element("pre", preview(fromBase64(item.payload)), "payload"));
  const proposed = item.proposed === null || item.proposed === undefined ? null : fromBase64(item.proposed);
  const proposedText = proposed === null ? "" : asText(proposed);
  const mode = element("select", "");
  mode.append(element("option", "text"), element("option", "base64"));
  const editor = document.createElement("textarea");
  editor.rows = 8;
  editor.spellcheck = false;
  if (proposed !== null && proposedText === null) {
    mode.value = "base64";
    editor.value = item.proposed;
  } else {
    editor.value = proposedText || "";
  }
  card.append(element("div", proposed === null ? "proposed: the handler's default (not shown for this protocol)" : `proposed${item.proposed_close ? " (then close)" : ""}:`, "muted"));
  card.append(editor);
  const buttons = element("div", "", "buttons");
  const button = (label, handler) => { const b = element("button", label); b.addEventListener("click", handler); buttons.append(b); };
  const edited = (close) => mode.value === "base64" ? { action: "send", response_base64: editor.value.trim(), close } : { action: "send", response: editor.value, close };
  button("Send proposed", () => answer(item.id, { action: "proposed" }, card));
  button("Send edited", () => answer(item.id, edited(false), card));
  button("Send edited, close", () => answer(item.id, edited(true), card));
  button("Close connection", () => answer(item.id, { action: "close" }, card));
  buttons.append(mode, element("span", "", "status countdown"));
  card.append(buttons);
  return card;
}

async function manual() {
  try {
    const response = await fetch("/api/manual", { credentials: "same-origin" });
    if (!response.ok) return;
    const body = await response.json();
    $("manual-section").hidden = !body.enabled;
    if (!body.enabled) return;
    const ids = new Set(body.pending.map((p) => p.id));
    for (const [id, card] of held) if (!ids.has(id)) { card.remove(); held.delete(id); }
    for (const item of body.pending) {
      if (!held.has(item.id)) {
        const card = heldCard(item);
        card.dataset.expires = item.expires_at_ms;
        held.set(item.id, card);
        $("manual").append(card);
      }
    }
    $("manual-info").textContent = held.size ? `${held.size} held; unanswered ones get the proposed answer after ${Math.round(body.timeout_ms / 1000)} s` : "nothing held";
  } catch (e) { /* poll() reports reachability */ }
}

function countdown() {
  for (const card of held.values()) {
    const status = card.querySelector(".countdown");
    if (status && !status.textContent.startsWith("not sent")) status.textContent = `${Math.max(0, Math.round((card.dataset.expires - Date.now()) / 1000))} s left`;
  }
}

async function paused() {
  try {
    const response = await fetch("/api/paused", { credentials: "same-origin" });
    if (!response.ok) return;
    const body = await response.json();
    $("paused-section").hidden = !body.hooks || body.paused.length === 0;
    $("paused").replaceChildren(...body.paused.map((p) => {
      const li = element("li", `pid ${text(p.pid)} ${p.process ? text(p.process.name) : ""} · hook ${text(p.hook)} · ${text(p.host)} ${text(p.request)} `);
      const resume = element("button", "Resume");
      resume.addEventListener("click", async () => {
        resume.disabled = true;
        await fetch(`/api/paused/${p.pid}/resume`, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: "{}" });
        paused();
      });
      li.append(resume);
      return li;
    }));
  } catch (e) { /* poll() reports reachability */ }
}

$("kind").addEventListener("change", renderRecords);
$("search").addEventListener("input", renderRecords);
$("pause").addEventListener("change", renderRecords);
poll();
summary();
setInterval(poll, 1000);
setInterval(summary, 2000);
manual();
paused();
setInterval(manual, 1000);
setInterval(paused, 2000);
setInterval(countdown, 500);

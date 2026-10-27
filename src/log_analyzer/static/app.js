"use strict";
/* Log Analyzer dashboard. All log-derived text is inserted with textContent (never innerHTML),
   because IPs, usernames and URL paths in logs are attacker-controlled. */

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const METRICS = {
  failed_logins: "Failed logins",
  successful_logins: "Successful logins",
  system_errors: "System errors",
  web_errors: "Web errors (4xx/5xx)",
  web_requests: "Web requests (ok)",
};
const state = { visible: new Set(["failed_logins", "successful_logins", "system_errors", "web_errors"]),
  data: null, timer: null };

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else e.setAttribute(k, v);
  }
  for (const kid of kids) if (kid) e.append(kid);
  return e;
}
function s(tag, attrs = {}, title) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (title) { const t = document.createElementNS(SVG_NS, "title"); t.textContent = title; e.append(t); }
  return e;
}
const fmt = (n) => Number(n).toLocaleString();
const fmtSize = (b) => b == null ? "missing" : b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`;

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Logan": "1", ...(opts.headers || {}) } });
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error((body && body.error) || `${res.status} ${res.statusText}`);
  return body;
}

function params() {
  const q = new URLSearchParams();
  for (const id of ["top", "threshold", "year"]) if ($(id).value) q.set(id, $(id).value);
  return q;
}

/* ---------- loading ---------- */
async function load() {
  try {
    const data = await api("/api/report?" + params());
    state.data = data;
    render(data);
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
    const q = params().toString();
    $("dl-json").href = "/api/report.json?" + q;
    $("dl-txt").href = "/api/report.txt?" + q;
  } catch (err) {
    showWarnings([`Could not load report: ${err.message}`]);
  }
}

function showWarnings(list) {
  const box = $("warnings");
  box.hidden = list.length === 0;
  box.textContent = list.join(" \u2022 ");
}

/* ---------- rendering ---------- */
function render(d) {
  showWarnings(d.warnings || []);
  renderFiles(d.files);
  const empty = d.files.length === 0;
  $("empty").hidden = !empty;
  $("dash").hidden = empty;
  if (empty) return;

  const compromised = d.alerts.possible_compromise_ips;
  const webTotal = d.web ? d.web.requests : 0;
  const kpis = [
    ["Failed logins", d.logins.failed, d.logins.failed ? "bad" : ""],
    ["Successful logins", d.logins.successful, "good"],
    ["Total errors", d.errors.total, d.errors.total ? "warn" : ""],
    ["Web requests", webTotal, ""],
    ["Brute-force IPs", d.alerts.brute_force_ips.length, d.alerts.brute_force_ips.length ? "bad" : ""],
    ["Possible compromise", compromised.length, compromised.length ? "bad" : "good"],
  ];
  const k = $("kpis"); k.replaceChildren();
  for (const [label, val, cls] of kpis) {
    k.append(h("div", { class: "kpi " + cls }, h("div", { class: "v", text: fmt(val) }), h("div", { class: "l", text: label })));
  }
  const range = d.summary.first_event ? `${d.summary.first_event.replace("T", " ")} \u2192 ${d.summary.last_event.replace("T", " ")}` : "no timestamps parsed";
  const lines = Object.values(d.summary.lines_read).reduce((x, y) => x + y, 0);
  $("range").textContent = `${fmt(lines)} lines read \u2022 ${range}`;

  renderAlerts(d);
  renderToggles();
  renderHourly(d.time_distribution.hourly);
  renderDaily(d.time_distribution.daily);

  const flagged = new Set(d.alerts.brute_force_ips.map(([ip]) => ip));
  table("t-failed-ip", d.logins.failed_by_ip, flagged);
  table("t-failed-user", d.logins.failed_by_user);
  table("t-success-user", d.logins.successful_by_user);
  table("t-top-ip", d.top_source_ips);
  table("t-methods", Object.entries(d.logins.methods).sort((a, b) => b[1] - a[1]));
  const statusCodes = (d.web && (d.web.status_codes || d.web.status_code)) || {};
  table("t-status", Object.entries(statusCodes), new Set(Object.keys(statusCodes).filter((c) => +c >= 400)));
  table("t-sys", d.errors.system_by_process);
  table("t-web", d.errors.web_by_status_path);
}

function renderFiles(files) {
  const ul = $("files"); ul.replaceChildren();
  for (const f of files) {
    const rm = h("button", { type: "button", "aria-label": `Remove ${f.name}`, title: "Remove", text: "\u00d7" });
    rm.addEventListener("click", async () => {
      try { await api("/api/files?id=" + encodeURIComponent(f.id), { method: "DELETE" }); } catch (e) { showWarnings([e.message]); }
      load();
    });
    ul.append(h("li", {}, h("span", { class: "tag", text: f.source }), h("span", { text: `${f.name} (${fmtSize(f.size)})` }), rm));
  }
}

function renderAlerts(d) {
  const box = $("alerts"); box.replaceChildren();
  const { brute_force_ips: bf, possible_compromise_ips: pc, threshold } = d.alerts;
  if (!bf.length) {
    box.append(h("div", { class: "alert" }, h("span", { class: "badge ok", text: "OK" }), h("span", { text: `No IP has ${threshold}+ failed logins.` })));
    return;
  }
  for (const [ip, n] of bf) {
    const row = h("div", { class: "alert" });
    const hit = pc.includes(ip);
    row.append(h("span", { class: "badge " + (hit ? "crit" : ""), text: hit ? "INVESTIGATE" : "BRUTE FORCE" }),
      h("code", { text: ip }),
      h("span", { text: hit ? `${fmt(n)} failures followed by a successful login` : `${fmt(n)} failed logins` }));
    box.append(row);
  }
}

function renderToggles() {
  const box = $("hourly-toggles"); box.replaceChildren();
  for (const [key, label] of Object.entries(METRICS)) {
    const b = h("button", { type: "button", "aria-pressed": String(state.visible.has(key)) });
    const dot = h("i"); dot.style.background = `var(--c-${key})`;
    b.append(dot, document.createTextNode(label));
    b.addEventListener("click", () => {
      state.visible.has(key) ? state.visible.delete(key) : state.visible.add(key);
      renderToggles(); renderHourly(state.data.time_distribution.hourly);
    });
    box.append(b);
  }
}

function niceMax(v) {
  if (v <= 5) return 5;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return v;
}

function frame(svg, W, H, M, max, xLabels) {
  for (let i = 0; i <= 4; i++) {
    const y = M.t + ((H - M.t - M.b) * i) / 4;
    svg.append(s("line", { class: "grid-line", x1: M.l, x2: W - M.r, y1: y, y2: y }));
    const t = s("text", { x: M.l - 6, y: y + 4, "text-anchor": "end" }); t.textContent = fmt(Math.round(max * (1 - i / 4)));
    svg.append(t);
  }
  for (const [x, label] of xLabels) {
    const t = s("text", { x, y: H - 8, "text-anchor": "middle" }); t.textContent = label; svg.append(t);
  }
}

function renderHourly(hourly) {
  const box = $("hourly"); box.replaceChildren();
  const keys = Object.keys(METRICS).filter((k) => state.visible.has(k) && hourly[k]);
  if (!keys.length) { box.append(h("p", { class: "none", text: "No data for the selected series." })); return; }
  const W = 640, H = 260, M = { l: 44, r: 12, t: 12, b: 28 };
  const max = niceMax(Math.max(1, ...keys.flatMap((k) => hourly[k])));
  const x = (i) => M.l + ((W - M.l - M.r) * i) / 23;
  const y = (v) => M.t + (H - M.t - M.b) * (1 - v / max);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Events per hour of day" });
  frame(svg, W, H, M, max, [0, 3, 6, 9, 12, 15, 18, 21, 23].map((i) => [x(i), String(i).padStart(2, "0")]));
  for (const key of keys) {
    const vals = hourly[key];
    svg.append(s("polyline", { class: "line", stroke: `var(--c-${key})`, points: vals.map((v, i) => `${x(i)},${y(v)}`).join(" ") }));
    vals.forEach((v, i) => { if (v) svg.append(s("circle", { class: "dot", cx: x(i), cy: y(v), r: 3.5, fill: `var(--c-${key})` }, `${METRICS[key]} \u2022 ${String(i).padStart(2, "0")}:00 \u2022 ${fmt(v)}`)); });
  }
  box.append(svg);
}

function renderDaily(daily) {
  const box = $("daily"); box.replaceChildren();
  const days = Object.keys(daily);
  if (!days.length) { box.append(h("p", { class: "none", text: "No timestamped events." })); return; }
  const W = 640, H = 260, M = { l: 52, r: 12, t: 12, b: 28 };
  const max = niceMax(Math.max(...Object.values(daily)));
  const slot = (W - M.l - M.r) / days.length, bw = Math.min(46, slot * 0.7);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Events per day" });
  const step = Math.ceil(days.length / 8);
  frame(svg, W, H, M, max, days.map((d, i) => [M.l + slot * (i + 0.5), d.slice(5)]).filter((_, i) => i % step === 0));
  days.forEach((d, i) => {
    const v = daily[d], bh = (H - M.t - M.b) * (v / max);
    svg.append(s("rect", { class: "col", x: M.l + slot * (i + 0.5) - bw / 2, y: H - M.b - bh, width: bw, height: bh, rx: 2 }, `${d} \u2022 ${fmt(v)} events`));
  });
  box.append(svg);
}

function table(id, rows, flagged = new Set()) {
  const box = $(id); box.replaceChildren();
  if (!rows || !rows.length) { box.append(h("p", { class: "none", text: "(none)" })); return; }
  const peak = Math.max(...rows.map((r) => r[1]));
  const t = h("table");
  for (const [k, v] of rows) {
    const bar = h("div", { class: "bar" + (flagged.has(String(k)) ? " flag" : "") });
    bar.style.width = `${Math.max(2, (v / peak) * 100)}%`;
    t.append(h("tr", { class: flagged.has(String(k)) ? "flag" : "" },
      h("td", { class: "k", text: String(k) }), h("td", { class: "b" }, bar), h("td", { class: "n", text: fmt(v) })));
  }
  box.append(t);
}

/* ---------- uploads ---------- */
function guessKind(name) {
  const n = name.toLowerCase();
  if (/(auth|secure|sshd)/.test(n)) return "auth";
  if (/(access|nginx|apache|httpd)/.test(n)) return "web";
  return "system";
}

async function upload(files) {
  const forced = $("kind").value;
  const status = $("upload-status");
  let i = 0;
  for (const f of files) {
    i++;
    const kind = forced === "auto" ? guessKind(f.name) : forced;
    status.textContent = `Uploading ${f.name} as ${kind} (${i}/${files.length})\u2026`;
    try {
      await api(`/api/upload?source=${kind}&filename=${encodeURIComponent(f.name)}`, { method: "POST", body: f });
    } catch (err) {
      status.textContent = `Upload failed for ${f.name}: ${err.message}`;
      await load();
      return;
    }
  }
  status.textContent = `Uploaded ${files.length} file(s).`;
  await load();
}

function wire() {
  const drop = $("drop"), picker = $("picker");
  drop.addEventListener("click", () => picker.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
  picker.addEventListener("change", () => { if (picker.files.length) upload([...picker.files]); picker.value = ""; });
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
  for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
  drop.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) upload([...e.dataTransfer.files]); });

  $("refresh").addEventListener("click", load);
  $("samples").addEventListener("click", async () => {
    try { await api("/api/samples", { method: "POST" }); } catch (e) { showWarnings([e.message]); return; }
    load();
  });
  $("clear").addEventListener("click", async () => {
    if (!state.data || !state.data.files.length || confirm("Remove all loaded log files?")) {
      await api("/api/clear", { method: "POST" }); $("upload-status").textContent = ""; load();
    }
  });
  for (const id of ["top", "threshold", "year"]) $(id).addEventListener("change", load);
  $("auto").addEventListener("change", () => {
    clearInterval(state.timer);
    const sec = +$("auto").value;
    if (sec) state.timer = setInterval(load, sec * 1000);
  });
}

wire();
load();

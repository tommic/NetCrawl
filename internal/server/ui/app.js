"use strict";
// Admin UI for netcrawl-server. Uses the admin API with the session
// cookie; no external dependencies, all data is inserted via textContent.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
// Theme: dark by default; the choice is remembered in this browser.
function applyTheme(theme) {
  if (theme === "light") document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  const sw = document.getElementById("theme-switch");
  if (sw) sw.setAttribute("aria-pressed", String(theme === "light"));
}
try { applyTheme(localStorage.getItem("netcrawl-theme")); } catch { /* storage blocked: stay dark */ }

let networks = [];
let currentTab = "overview";

const pages = {
  overview: ["Übersicht", "Auf einen Blick: Was hat sich in Ihrem Netz verändert?"],
  events: ["Ereignisse", "Änderungen im Netz, neueste zuerst."],
  hosts: ["Inventar", "Alle gefundenen Hosts. Zeile anklicken für Details und einen eigenen Namen."],
  networks: ["Netze & Crawler", "Welche Netze wie oft geprüft werden und welche Crawler das übernehmen."],
  settings: ["Benachrichtigungen", "Änderungen per Discord melden."],
  admin: ["Administration", "Einzelne Jobs, Job-Verlauf und Audit-Log."],
};
let installer = false;

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  let data = null;
  const text = await resp.text();
  if (text) { try { data = JSON.parse(text); } catch { data = { error: text }; } }
  if (!resp.ok) {
    const err = new Error((data && data.error) || resp.statusText);
    err.status = resp.status;
    throw err;
  }
  return data;
}

function fmt(ts) {
  if (!ts) return "–";
  return new Date(ts).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function cell(tr, text, cls) {
  const td = el("td", text, cls);
  tr.appendChild(td);
  return td;
}

function emptyRow(tbody, cols, text) {
  const tr = document.createElement("tr");
  const td = cell(tr, text, "hint");
  td.colSpan = cols;
  tbody.appendChild(tr);
}

function list(v) {
  return String(v || "").split(",").map((t) => t.trim()).filter(Boolean);
}

function networkName(id) {
  const n = networks.find((x) => x.id === id);
  return n ? n.name : "#" + id;
}

function message(sel, text, isError) {
  const m = $(sel);
  m.className = isError ? "error" : "ok";
  m.textContent = text;
  m.hidden = false;
}

// ---- login ----

function showLogin() {
  $("#login-view").hidden = false;
  $("#app-view").hidden = true;
  $("#sidebar").hidden = true;
  document.body.classList.remove("signed-in");
}

function showVersion(v) {
  $("#version").textContent = v ? "Version " + v : "";
}

async function showApp(username) {
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#sidebar").hidden = false;
  document.body.classList.add("signed-in");
  $("#who").textContent = username;
  await refresh();
}

function selectTab(tab) {
  if (tab === "settings" && currentTab !== "settings") renderNotify(true);
  currentTab = tab;
  for (const b of $$(".tab")) {
    b.classList.toggle("active", b.dataset.tab === tab);
    if (b.dataset.tab === tab) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  for (const p of $$(".panel")) p.hidden = p.dataset.panel !== tab;
  $("#page-title").textContent = pages[tab][0];
  $("#page-sub").textContent = pages[tab][1];
  refresh();
}

// ---- data ----

async function refresh() {
  try {
    networks = await api("GET", "/api/v1/admin/networks");
    fillNetworkSelects();
    const crawlers = await api("GET", "/api/v1/admin/crawlers");
    fillCrawlerSelects(crawlers);
    await updateBadge();
    renderLastDiscovery();
    switch (currentTab) {
      case "overview": return renderOverview(crawlers);
      case "events": return renderEvents();
      case "hosts": return renderHosts();
      case "networks": renderCrawlers(crawlers); await renderNetworks(); return renderPublicURL();
      case "admin": await renderJobs(); return renderAudit();
      case "settings": return renderNotify(false);
    }
  } catch (e) {
    if (e.status === 401) showLogin();
  }
}

function fillNetworkSelects() {
  for (const sel of [$("#ev-network"), $("#host-network")]) {
    const cur = sel.value;
    sel.replaceChildren(new Option("Alle Netze", "0"));
    for (const n of networks) sel.appendChild(new Option(n.name, String(n.id)));
    sel.value = cur || "0";
    if (sel.selectedIndex < 0) sel.value = "0";
  }
}

function fillCrawlerSelects(crawlers) {
  for (const sel of $$(".crawler-select")) {
    const cur = sel.value;
    sel.replaceChildren();
    for (const c of crawlers) sel.appendChild(new Option(c.id, c.id));
    if (cur) sel.value = cur;
  }
}

async function updateBadge() {
  const events = await api("GET", "/api/v1/admin/events?limit=200");
  const since = Date.now() - 24 * 3600 * 1000;
  const n = events.filter((e) => e.severity !== "info" && new Date(e.at).getTime() > since).length;
  const badge = $("#badge");
  badge.textContent = String(n);
  badge.hidden = n === 0;
}

const severityLabel = { info: "Info", warning: "Warnung", critical: "Kritisch" };

function ago(ts) {
  const min = Math.round((Date.now() - new Date(ts).getTime()) / 60000);
  if (min < 1) return "gerade eben";
  if (min < 60) return `vor ${min} Min.`;
  const h = Math.round(min / 60);
  if (h < 48) return `vor ${h} Std.`;
  return `vor ${Math.round(h / 24)} Tagen`;
}

function renderLastDiscovery() {
  const times = networks.map((n) => n.discovery_done_at).filter(Boolean).map((t) => new Date(t).getTime());
  const box = $("#last-discovery");
  box.replaceChildren();
  if (!times.length) return;
  box.append(el("span", undefined, "dot dot-ok"), document.createTextNode(" Letzte Erkennung: " + ago(Math.max(...times))));
}

function sevPill(sev) {
  return el("span", severityLabel[sev] || sev, "sev sev-" + sev);
}

async function renderOverview(crawlers) {
  const [hosts, events] = await Promise.all([
    api("GET", "/api/v1/admin/hosts?network_id=0"),
    api("GET", "/api/v1/admin/events?limit=200"),
  ]);
  const since = Date.now() - 24 * 3600 * 1000;
  const recent = events.filter((e) => new Date(e.at).getTime() > since);
  const online = hosts.filter((h) => h.online).length;
  const offInfo = hosts.filter((h) => !h.online && h.offline_level === "info").length;
  const offWarn = hosts.length - online - offInfo;
  const active = crawlers.filter((c) => c.enabled);
  const warnings = recent.filter((e) => e.severity !== "info").length;

  $("#kpi-online").textContent = String(online);
  $("#kpi-new").textContent = String(recent.filter((e) => e.type === "host.new").length);
  $("#kpi-warn").textContent = String(warnings);
  $("#kpi-crawlers").textContent = String(active.filter((c) => !crawlerOnline(c)).length);

  const pill = $("#ov-warn");
  pill.textContent = `${warnings} Warnung${warnings === 1 ? "" : "en"} (24 h)`;
  pill.hidden = warnings === 0;

  const tbody = $("#ov-events");
  tbody.replaceChildren();
  for (const e of events.slice(0, 6)) {
    const tr = document.createElement("tr");
    cell(tr, "").appendChild(sevPill(e.severity));
    cell(tr, fmt(e.at), "muted nowrap");
    const td = cell(tr, "");
    td.append(el("div", e.message, "strong"), el("div", networkName(e.network_id), "muted small"));
    tbody.appendChild(tr);
  }
  if (!events.length) emptyRow(tbody, 3, networks.length ? "Noch keine Änderungen." : "Noch kein Netz angelegt – unter „Netze & Crawler“ ein Netz anlegen.");

  // Donut: share of hosts online.
  const pct = hosts.length ? Math.round((online / hosts.length) * 100) : 0;
  const c = 2 * Math.PI * 48;
  $("#donut-arc").setAttribute("stroke-dasharray", `${(c * pct) / 100} ${c}`);
  $("#donut-pct").textContent = hosts.length ? pct + " %" : "–";
  $("#donut").setAttribute("aria-label", hosts.length ? `${pct} Prozent der Hosts online` : "Noch keine Hosts");
  $("#lg-online").textContent = String(online);
  $("#lg-info").textContent = String(offInfo);
  $("#lg-warn").textContent = String(offWarn);
  const enabledNets = networks.filter((n) => n.enabled);
  $("#ov-discover").disabled = !enabledNets.length;
  $("#ov-portscan").disabled = !enabledNets.some((n) => n.discovery_done_at);

  const list = $("#ov-crawlers");
  list.replaceChildren();
  for (const cr of crawlers) {
    const li = document.createElement("li");
    const [label, cls] = crawlerState(cr);
    const nets = networks.filter((n) => n.crawler_id === cr.id).map((n) => n.name).join(", ");
    li.append(el("span", undefined, "dot " + (cls === "status-completed" ? "dot-ok" : cls === "status-expired" ? "dot-bad" : "dot-warn")),
      el("span", cr.id, "strong"), el("span", nets ? "· " + nets : "", "muted"), el("span", label, "push " + cls));
    list.appendChild(li);
  }
  if (!crawlers.length) list.appendChild(el("li", "Noch kein Crawler angelegt.", "hint"));
}

async function scanAll(kind, btn) {
  const targets = networks.filter((n) => n.enabled && (kind === "discovery" || n.discovery_done_at));
  const msg = $("#ov-scan-msg");
  btn.disabled = true;
  try {
    await Promise.all(targets.map((n) => api("POST", `/api/v1/admin/networks/${n.id}/scan`, { kind })));
    msg.className = "hint";
    msg.textContent = `${kind === "discovery" ? "Erkennung" : "Portscan"} für ${targets.length} Netz${targets.length === 1 ? "" : "e"} geplant. Die Crawler holen die Jobs beim nächsten Abfragen ab.`;
  } catch (e) {
    msg.className = "error";
    msg.textContent = "Nicht möglich: " + e.message;
  }
  msg.hidden = false;
  btn.disabled = false;
}

async function renderEvents() {
  const nid = $("#ev-network").value;
  const baseline = $("#ev-baseline").checked ? "&baseline=1" : "";
  const events = await api("GET", `/api/v1/admin/events?limit=200&network_id=${nid}${baseline}`);
  const tbody = $("#events");
  tbody.replaceChildren();
  for (const e of events) {
    const tr = document.createElement("tr");
    cell(tr, fmt(e.at));
    cell(tr, networkName(e.network_id));
    const td = cell(tr, "");
    td.appendChild(el("span", severityLabel[e.severity] || e.severity, "sev sev-" + e.severity));
    const msg = cell(tr, e.message);
    if (e.baseline) msg.appendChild(el("span", " Initialbestand", "hint"));
    tbody.appendChild(tr);
  }
  if (!events.length) {
    emptyRow(tbody, 4, networks.length
      ? "Noch keine Änderungen. Der Initialbestand ist ausgeblendet (Haken oben rechts)."
      : "Noch kein Netz angelegt – unter „Netze“ ein Netz anlegen.");
  }
}

// hostName renders a host's name: the custom name (marked, with the
// discovered hostname as tooltip) or the discovered hostname.
function hostName(h) {
  if (h.custom_name) {
    const span = el("span", h.custom_name, "custom-name");
    span.title = "Eigener Name – gefundener Hostname: " + (h.hostname || "keiner");
    return span;
  }
  return document.createTextNode(h.hostname || "–");
}

function hostStatus(h) {
  return h.online ? ["online", "status-completed"]
    : ["offline (" + (severityLabel[h.offline_level] || h.offline_level) + ")", "status-expired"];
}

let selectedHost = null; // { network_id, ip }

async function renderHosts() {
  const nid = $("#host-network").value;
  const hosts = await api("GET", `/api/v1/admin/hosts?network_id=${nid}`);
  const tbody = $("#hosts");
  tbody.replaceChildren();
  for (const h of hosts) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    cell(tr, networkName(h.network_id));
    cell(tr, h.ip, "mono");
    cell(tr, "").appendChild(hostName(h));
    const [status, cls] = hostStatus(h);
    cell(tr, "").appendChild(el("span", status, "pill " + cls));
    cell(tr, h.ports_scanned_at ? (h.ports.map((p) => p.port).join(", ") || "keine") : "noch kein Portscan");
    cell(tr, fmt(h.first_seen));
    cell(tr, fmt(h.last_seen));
    const td = cell(tr, "");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = h.important;
    box.addEventListener("click", (ev) => ev.stopPropagation());
    box.addEventListener("change", async () => {
      try {
        await api("POST", "/api/v1/admin/hosts/important", { network_id: h.network_id, ip: h.ip, important: box.checked });
        h.important = box.checked;
      } catch { box.checked = !box.checked; }
    });
    td.appendChild(box);
    const open = () => {
      selectedHost = { network_id: h.network_id, ip: h.ip };
      for (const r of tbody.children) r.classList.remove("selected");
      tr.classList.add("selected");
      showHost(h);
    };
    tr.tabIndex = 0; // keyboard: Tab to a row, Enter opens it
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (ev) => {
      if (ev.target === tr && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); open(); }
    });
    if (selectedHost && selectedHost.network_id === h.network_id && selectedHost.ip === h.ip) tr.classList.add("selected");
    tbody.appendChild(tr);
  }
  if (!hosts.length) emptyRow(tbody, 8, "Noch keine Hosts – die erste Host-Erkennung läuft nach dem Anlegen eines Netzes.");
  const sel = selectedHost && hosts.find((h) => h.network_id === selectedHost.network_id && h.ip === selectedHost.ip);
  if (sel) {
    // Do not throw away a name the user is typing (auto refresh).
    const input = $("#host-name");
    if (!input || (document.activeElement !== input && input.value === input.dataset.saved)) showHost(sel);
  } else if ($("#host-dialog").open) $("#host-dialog").close();
}

// The host detail opens as a panel over the list (modal <dialog>), so it
// appears where the user is, however long the list is.
function setupHostDialog() {
  const dlg = $("#host-dialog");
  dlg.addEventListener("close", () => {
    const sel = selectedHost && $$("#hosts tr.selected")[0];
    selectedHost = null;
    for (const r of $("#hosts").children) r.classList.remove("selected");
    if (sel) sel.focus();
  });
  // A click on the dimmed area next to the panel closes it.
  dlg.addEventListener("click", (ev) => { if (ev.target === dlg) dlg.close(); });
}

async function showHost(h) {
  const dlg = $("#host-dialog");
  const box = $("#host-detail");
  box.replaceChildren();
  if (!dlg.open) dlg.showModal();

  const head = el("div", undefined, "title-row detail-head");
  const title = el("h3", (h.custom_name || h.hostname || h.ip) + (h.custom_name || h.hostname ? " – " + h.ip : ""));
  title.id = "host-title";
  const close = el("button", "Schließen", "ghost small");
  close.type = "button";
  close.addEventListener("click", () => dlg.close());
  head.append(title, close);
  box.appendChild(head);

  const facts = el("dl", undefined, "facts");
  const fact = (k, v, cls) => { facts.append(el("dt", k), el("dd", v, cls)); };
  const [status, cls] = hostStatus(h);
  fact("Netz", networkName(h.network_id));
  fact("IP-Adresse", h.ip, "mono");
  fact("Gefundener Hostname", h.hostname || "keiner (kein Reverse-DNS-Eintrag)");
  fact("Eigener Name", h.custom_name || "–");
  fact("Status", status, cls);
  fact("Zuerst gesehen", fmt(h.first_seen));
  fact("Zuletzt gesehen", fmt(h.last_seen));
  fact("Letzter Portscan", h.ports_scanned_at ? fmt(h.ports_scanned_at) : "noch keiner");
  fact("Wichtig", h.important ? "ja" : "nein");
  const left = el("div", undefined, "detail-col");
  const right = el("div", undefined, "detail-col");
  const cols = el("div", undefined, "detail-cols");
  cols.append(left, right);
  box.appendChild(cols);
  left.appendChild(facts);

  // Custom name.
  const form = document.createElement("form");
  form.className = "row";
  const label = el("label", "Eigener Name");
  const input = document.createElement("input");
  input.id = "host-name";
  input.maxLength = 64;
  input.value = h.custom_name;
  input.dataset.saved = h.custom_name;
  input.placeholder = h.hostname || "z. B. Drucker Büro";
  label.appendChild(input);
  const save = el("button", "Speichern");
  save.type = "submit";
  form.append(label, save);
  if (h.custom_name) {
    const reset = el("button", "Gefundenen Namen verwenden", "ghost");
    reset.type = "button";
    reset.addEventListener("click", () => setName(""));
    form.appendChild(reset);
  }
  const msg = el("p", undefined, "hint");
  msg.hidden = true;
  async function setName(name) {
    try {
      await api("POST", "/api/v1/admin/hosts/name", { network_id: h.network_id, ip: h.ip, name });
      await renderHosts();
    } catch (e) {
      msg.className = "error";
      msg.textContent = "Fehler: " + e.message;
      msg.hidden = false;
    }
  }
  form.addEventListener("submit", (ev) => { ev.preventDefault(); setName(input.value); });
  left.append(form, msg);

  // Open ports.
  right.appendChild(el("h3", "Offene Ports"));
  if (!h.ports_scanned_at) right.appendChild(el("p", "Noch kein Portscan für diesen Host.", "hint"));
  else if (!h.ports.length) right.appendChild(el("p", "Keine offenen Ports gefunden.", "hint"));
  else {
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const hr = document.createElement("tr");
    for (const t of ["Port", "Offen seit", "Zuletzt bestätigt"]) hr.appendChild(el("th", t));
    thead.appendChild(hr);
    const tbody = document.createElement("tbody");
    for (const p of h.ports) {
      const tr = document.createElement("tr");
      cell(tr, String(p.port), "mono");
      cell(tr, fmt(p.first_seen));
      cell(tr, fmt(p.last_seen));
      tbody.appendChild(tr);
    }
    table.append(thead, tbody);
    right.appendChild(table);
  }

  // Events of this host.
  right.appendChild(el("h3", "Ereignisse"));
  const evBox = el("div");
  right.appendChild(evBox);
  let events;
  try {
    events = await api("GET", `/api/v1/admin/events?limit=20&baseline=1&network_id=${h.network_id}&ip=${encodeURIComponent(h.ip)}`);
  } catch (e) { evBox.appendChild(el("p", "Fehler: " + e.message, "error")); return; }
  if (!events.length) { evBox.appendChild(el("p", "Keine Ereignisse.", "hint")); return; }
  const table = document.createElement("table");
  const tbody = document.createElement("tbody");
  for (const e of events) {
    const tr = document.createElement("tr");
    cell(tr, fmt(e.at));
    cell(tr, "").appendChild(el("span", severityLabel[e.severity] || e.severity, "sev sev-" + e.severity));
    const m = cell(tr, e.message);
    if (e.baseline) m.appendChild(el("span", " Initialbestand", "hint"));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  evBox.appendChild(table);
}

async function renderNetworks() {
  const tbody = $("#networks");
  tbody.replaceChildren();
  for (const n of networks) {
    const tr = document.createElement("tr");
    cell(tr, n.name);
    cell(tr, n.crawler_id);
    cell(tr, n.targets.join(", "), "mono");
    cell(tr, n.deny.join(", ") || "–", "mono");
    cell(tr, `${n.hosts_online} / ${n.hosts} online`);
    cell(tr, fmt(n.discovery_done_at) + ` (alle ${n.discovery_interval_minutes} Min.)`);
    cell(tr, fmt(n.portscan_done_at) + ` (alle ${n.portscan_interval_hours} Std.)`);
    cell(tr, n.enabled ? "ja" : "nein");
    const td = cell(tr, "");
    for (const [kind, text] of [["discovery", "Erkennung jetzt"], ["ports", "Portscan jetzt"]]) {
      const b = el("button", text, "ghost small");
      b.addEventListener("click", async () => {
        try {
          await api("POST", `/api/v1/admin/networks/${n.id}/scan`, { kind });
          b.textContent = "geplant ✓";
        } catch (e) { b.textContent = e.message; }
      });
      td.appendChild(b);
    }
    tbody.appendChild(tr);
  }
  if (!networks.length) emptyRow(tbody, 9, "Noch kein Netz angelegt.");
}

function jobStatus(j) {
  if (j.expired) return ["abgelaufen", "status-expired"];
  return ({ pending: ["wartet", "status-pending"], delivered: ["beim Crawler", "status-delivered"], completed: ["fertig", "status-completed"] })[j.status] || [j.status, ""];
}

async function renderJobs() {
  const jobs = await api("GET", "/api/v1/admin/jobs?limit=100");
  const tbody = $("#jobs");
  tbody.replaceChildren();
  for (const j of jobs) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    const [label, cls] = jobStatus(j);
    cell(tr, fmt(j.created_at));
    cell(tr, (j.kind === "discovery" ? "Erkennung" : "Portscan") + (j.network_id ? " · " + networkName(j.network_id) : ""));
    cell(tr, j.crawler_id);
    cell(tr, label, cls);
    cell(tr, j.targets.length > 3 ? `${j.targets.slice(0, 3).join(", ")} … (${j.targets.length})` : j.targets.join(", "));
    cell(tr, j.ports.length > 8 ? `${j.ports.length} Ports` : j.ports.join(", "));
    cell(tr, fmt(j.expires_at));
    tr.addEventListener("click", () => showJob(j.id));
    tbody.appendChild(tr);
  }
  if (!jobs.length) emptyRow(tbody, 7, "Noch keine Jobs.");
}

async function showJob(id) {
  const box = $("#job-detail");
  box.hidden = false;
  box.replaceChildren();
  let j;
  try { j = await api("GET", "/api/v1/admin/jobs/" + encodeURIComponent(id)); }
  catch (e) { box.textContent = "Fehler: " + e.message; return; }
  box.appendChild(el("h2", "Job " + j.id));
  if (!j.result) {
    box.appendChild(el("p", j.status === "completed" ? "Kein Ergebnis gespeichert." : "Noch kein Ergebnis – der Crawler fragt alle 60 Sekunden nach.", "hint"));
    return;
  }
  const table = document.createElement("table");
  const head = document.createElement("thead");
  const hr = document.createElement("tr");
  for (const t of ["Netz", "Host", "Offene Ports"]) hr.appendChild(el("th", t));
  head.appendChild(hr);
  table.appendChild(head);
  const tbody = document.createElement("tbody");
  for (const net of j.result.networks || []) {
    for (const [ip, host] of Object.entries(net.hosts || {})) {
      const tr = document.createElement("tr");
      cell(tr, net.network);
      cell(tr, ip + (host.hostname ? " (" + host.hostname + ")" : ""));
      cell(tr, (host.ports || []).join(", ") || "keine (Host antwortet)");
      tbody.appendChild(tr);
    }
  }
  if (!tbody.children.length) emptyRow(tbody, 3, "Kein Host hat geantwortet.");
  table.appendChild(tbody);
  box.appendChild(table);
  const details = document.createElement("details");
  details.append(el("summary", "Rohdaten (JSON)"), el("pre", JSON.stringify(j.result, null, 2)));
  box.appendChild(details);
}

// A crawler polls every 60 s; three missed polls count as offline.
function crawlerOnline(c) {
  return c.last_seen_at && Date.now() - new Date(c.last_seen_at).getTime() < 3 * 60 * 1000;
}

function crawlerState(c) {
  if (!c.enabled) return ["deaktiviert", "status-expired"];
  if (c.reinstall_required) return ["Neuinstallation nötig", "status-pending"];
  if (crawlerOnline(c)) return ["online", "status-completed"];
  return [c.last_seen_at ? "offline" : "noch nie verbunden", "status-expired"];
}

function renderCrawlers(crawlers) {
  const tbody = $("#crawlers");
  tbody.replaceChildren();
  for (const c of crawlers) {
    const tr = document.createElement("tr");
    cell(tr, c.id, "strong");
    const [state, stateCls] = crawlerState(c);
    cell(tr, "").appendChild(el("span", state, "pill " + stateCls));
    cell(tr, c.allow.join(", "), "mono");
    cell(tr, String(c.max_hosts));
    cell(tr, fmt(c.last_seen_at));
    const td = cell(tr, "");
    if (installer && c.enabled) {
      const b = el("button", "Installationsbefehl", "ghost small");
      b.type = "button";
      b.addEventListener("click", () => {
        if (c.last_seen_at && !confirm(`Ein neuer Installationsbefehl ersetzt beim Ausführen das Secret von „${c.id}“. Ein bereits installierter Crawler mit dem alten Secret funktioniert danach nicht mehr. Fortfahren?`)) return;
        showInstall(c.id, true);
      });
      td.appendChild(b);
    }
    if (installer && c.enabled) {
      const e = el("button", "Freigabe ändern", "ghost small");
      e.type = "button";
      e.addEventListener("click", () => showEdit(c));
      td.appendChild(e);
    }
    const t = el("button", c.enabled ? "Deaktivieren" : "Aktivieren", "ghost small");
    t.type = "button";
    t.addEventListener("click", async () => {
      if (c.enabled && !confirm(`Crawler „${c.id}“ deaktivieren? Er bekommt keine Jobs mehr, seine Ergebnisse werden abgelehnt.`)) return;
      try {
        await api("PUT", `/api/v1/admin/crawlers/${encodeURIComponent(c.id)}`, { enabled: !c.enabled });
        await refresh();
      } catch (e) {
        alert("Nicht möglich: " + e.message);
      }
    });
    td.appendChild(t);
    tbody.appendChild(tr);
  }
  if (!crawlers.length) emptyRow(tbody, 6, "Noch kein Crawler angelegt.");
}

// showInstall creates a one-time install command and shows it.
async function showInstall(id, reverseDNS) {
  const box = $("#install-box");
  box.replaceChildren();
  box.hidden = false;
  try {
    const v = await api("POST", `/api/v1/admin/crawlers/${encodeURIComponent(id)}/enroll`, { reverse_dns: reverseDNS });
    box.className = "install";
    const pre = el("pre", v.command);
    const copy = el("button", "Kopieren", "small");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(v.command);
        copy.textContent = "Kopiert";
      } catch {
        // No clipboard API on plain http: select the text instead.
        const range = document.createRange();
        range.selectNodeContents(pre);
        getSelection().removeAllRanges();
        getSelection().addRange(range);
        copy.textContent = "Markiert – mit Strg+C kopieren";
      }
    });
    const review = document.createElement("details");
    review.append(el("summary", "Skript erst ansehen, dann ausführen"), el("pre", v.download_command));
    const pin = v.tls_pin ? `-k --pinnedpubkey '${v.tls_pin}' ` : "";
    const remove = document.createElement("details");
    remove.append(
      el("summary", "Alte Installation entfernen"),
      el("p", "Auf demselben Rechner ersetzt der Befehl oben die alte Installation automatisch. Lief der Crawler bisher auf einem anderen Rechner, dort aufräumen mit:", "hint"),
      el("pre", `curl -fsS ${pin}'${v.server_url}/install/uninstall' | sudo sh`),
      el("p", "Ein alter Crawler, dessen Secret ersetzt wurde, beendet sich nach etwa drei Minuten auch von selbst.", "hint"));
    box.append(
      el("h3", `Crawler „${v.crawler_id}“ installieren`),
      el("p", "Auf dem Crawler-Rechner (Debian/Ubuntu/Raspberry Pi OS mit systemd, amd64 oder arm64) als Benutzer mit sudo ausführen:"),
      pre, copy, review, remove,
      el("p", `Gilt einmal, bis ${fmt(v.expires_at)}. Das Ausführen ersetzt das Secret des Crawlers.` +
        (v.tls_pin ? " Der Befehl prüft den Schlüssel des Servers (selbstsigniertes Zertifikat)." : ""), "hint"),
    );
    box.scrollIntoView({ block: "nearest" });
  } catch (e) {
    box.className = "error";
    box.textContent = "Installationsbefehl nicht möglich: " + e.message;
  }
}

// renderNotify shows the notification settings. full=false (periodic
// refresh) only updates the status line, so typing is not interrupted.
async function renderNotify(full) {
  const v = await api("GET", "/api/v1/admin/notifications");
  const st = $("#notify-status");
  if (!v.discord_configured) st.textContent = "Noch kein Webhook eingerichtet.";
  else {
    let t = `Webhook: ${v.discord_hint} · ${v.enabled ? "aktiv" : "pausiert"}`;
    if (v.last_sent_at) t += ` · zuletzt gesendet ${fmt(v.last_sent_at)}`;
    st.textContent = t;
  }
  if (v.last_error) {
    const e = el("span", ` · Fehler: ${v.last_error}`, "error");
    st.appendChild(e);
  }
  $("#notify-clear").hidden = !v.discord_configured;
  if (!full) return;
  const f = $("#notify-form");
  f.discord_url.value = "";
  f.discord_url.placeholder = v.discord_configured ? "gespeichert – leer lassen, um sie zu behalten" : "https://discord.com/api/webhooks/…";
  f.min_severity.value = v.min_severity;
  f.enabled.checked = v.enabled;
}

// showEdit opens the release editor for a crawler.
function showEdit(c) {
  $("#install-box").hidden = true;
  const box = $("#edit-box");
  $("#edit-id").textContent = c.id;
  const f = $("#edit-form");
  f.dataset.id = c.id;
  f.allow.value = c.allow.join(", ");
  f.max_hosts.value = c.max_hosts;
  $("#edit-msg").hidden = true;
  box.hidden = false;
  box.scrollIntoView({ block: "nearest" });
}

// renderPublicURL shows the server address card when crawlers cannot be
// installed yet, suggesting the address this page was opened with.
async function renderPublicURL() {
  const v = await api("GET", "/api/v1/admin/settings/public-url");
  const card = $("#public-url-card");
  const f = $("#public-url-form");
  if (v.source === "env") { card.hidden = true; return; }
  card.hidden = false;
  if (v.public_url) {
    $("#public-url-text").textContent = `Crawler erreichen den Server unter ${v.public_url}. Nur ändern, wenn sich die Adresse des Servers ändert.`;
    if (document.activeElement !== f.public_url) f.public_url.value = v.public_url;
  } else {
    $("#public-url-text").textContent = "Damit es einen Installationsbefehl gibt, muss der Server wissen, unter welcher Adresse die Crawler ihn erreichen. Vorschlag: die Adresse, unter der diese Seite gerade geöffnet ist.";
    if (!f.public_url.value) f.public_url.value = location.origin;
  }
}

async function renderAudit() {
  const audit = await api("GET", "/api/v1/admin/audit?limit=100");
  const tbody = $("#audit");
  tbody.replaceChildren();
  for (const e of audit) {
    const tr = document.createElement("tr");
    cell(tr, fmt(e.at));
    cell(tr, e.actor);
    cell(tr, e.action);
    cell(tr, e.details !== null ? JSON.stringify(e.details) : "", "mono small");
    tbody.appendChild(tr);
  }
}

// ---- forms ----

document.addEventListener("DOMContentLoaded", async () => {
  for (const b of $$(".tab")) b.addEventListener("click", () => selectTab(b.dataset.tab));
  setupHostDialog();
  $("#theme-switch").addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    applyTheme(theme);
    try { localStorage.setItem("netcrawl-theme", theme); } catch { /* not remembered */ }
  });
  applyTheme(document.documentElement.dataset.theme || "dark");
  for (const b of $$("[data-goto]")) b.addEventListener("click", () => selectTab(b.dataset.goto));
  $("#ov-discover").addEventListener("click", (ev) => scanAll("discovery", ev.currentTarget));
  $("#ov-portscan").addEventListener("click", (ev) => scanAll("ports", ev.currentTarget));
  $("#ev-network").addEventListener("change", renderEvents);
  $("#ev-baseline").addEventListener("change", renderEvents);
  $("#host-network").addEventListener("change", renderHosts);
  $("#refresh").addEventListener("click", refresh);

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    $("#login-error").hidden = true;
    try {
      const me = await api("POST", "/api/v1/admin/login", { username: f.get("username"), password: f.get("password") });
      ev.target.reset();
      installer = !!me.installer;
      showVersion(me.version);
      await showApp(me.username);
    } catch (e) {
      $("#login-error").textContent = e.status === 429 ? "Zu viele Fehlversuche, bitte später erneut versuchen." : "Benutzer oder Passwort falsch.";
      $("#login-error").hidden = false;
    }
  });

  $("#logout").addEventListener("click", async () => {
    try { await api("POST", "/api/v1/admin/logout"); } catch {}
    showLogin();
  });

  $("#network-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    try {
      const n = await api("POST", "/api/v1/admin/networks", {
        crawler_id: f.get("crawler_id"),
        name: f.get("name"),
        targets: list(f.get("targets")),
        deny: list(f.get("deny")),
        discovery_interval_minutes: parseInt(f.get("discovery"), 10),
        portscan_interval_hours: parseInt(f.get("portscan"), 10),
        scan_preset: f.get("scan_preset"),
        reverse_dns: f.get("reverse_dns") === "on",
      });
      message("#network-msg", `Netz „${n.name}“ angelegt. Die erste Host-Erkennung startet in Kürze, danach der Portscan.`);
      ev.target.reset();
      await refresh();
    } catch (e) {
      message("#network-msg", "Abgelehnt: " + e.message, true);
    }
  });

  $("#job-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    try {
      const j = await api("POST", "/api/v1/admin/jobs", {
        crawler_id: f.get("crawler_id"),
        targets: list(f.get("target")),
        ports: list(f.get("ports")).map((p) => parseInt(p, 10)).filter((p) => !Number.isNaN(p)),
        ttl_seconds: parseInt(f.get("ttl"), 10) * 60,
      });
      message("#job-msg", "Job angelegt. Der Crawler holt ihn beim nächsten Abfragen ab (alle 60 s).");
      await refresh();
      showJob(j.id);
    } catch (e) {
      message("#job-msg", "Abgelehnt: " + e.message, true);
    }
  });

  $("#notify-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try {
      await api("PUT", "/api/v1/admin/notifications", {
        discord_url: f.discord_url.value.trim(), min_severity: f.min_severity.value, enabled: f.enabled.checked,
      });
      message("#notify-msg", "Gespeichert. Gemeldet werden Änderungen ab jetzt.");
      await renderNotify(true);
    } catch (e) {
      message("#notify-msg", "Nicht gespeichert: " + e.message, true);
    }
  });
  $("#notify-test").addEventListener("click", async () => {
    try {
      await api("POST", "/api/v1/admin/notifications/test", {});
      message("#notify-msg", "Testnachricht gesendet – bitte im Discord-Kanal nachsehen.");
    } catch (e) {
      message("#notify-msg", "Test fehlgeschlagen: " + e.message, true);
    }
    await renderNotify(false);
  });
  $("#notify-clear").addEventListener("click", async () => {
    if (!confirm("Webhook entfernen? Benachrichtigungen werden damit abgeschaltet.")) return;
    try {
      const f = $("#notify-form");
      await api("PUT", "/api/v1/admin/notifications", { clear_discord_url: true, min_severity: f.min_severity.value, enabled: false });
      message("#notify-msg", "Webhook entfernt.");
      await renderNotify(true);
    } catch (e) {
      message("#notify-msg", "Nicht möglich: " + e.message, true);
    }
  });

  $("#public-url-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await api("PUT", "/api/v1/admin/settings/public-url", { public_url: ev.target.public_url.value.trim() });
      installer = true;
      message("#public-url-msg", "Gespeichert. Installationsbefehle verwenden jetzt diese Adresse.");
      await refresh();
    } catch (e) {
      message("#public-url-msg", "Nicht gespeichert: " + e.message, true);
    }
  });
  $("#edit-cancel").addEventListener("click", () => { $("#edit-box").hidden = true; });
  $("#edit-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    const id = f.dataset.id;
    if (!confirm(`Freigabe von „${id}“ ändern? Der Crawler muss danach neu installiert werden; bis dahin bleibt seine alte Freigabe aktiv.`)) return;
    try {
      await api("PUT", `/api/v1/admin/crawlers/${encodeURIComponent(id)}`, {
        allow: list(f.allow.value), max_hosts: parseInt(f.max_hosts.value, 10),
      });
      $("#edit-box").hidden = true;
      await refresh();
      await showInstall(id, f.reverse_dns.checked);
    } catch (e) {
      message("#edit-msg", "Abgelehnt: " + e.message, true);
    }
  });

  $("#crawler-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const box = $("#crawler-msg");
    box.replaceChildren();
    box.hidden = false;
    try {
      const c = await api("POST", "/api/v1/admin/crawlers", {
        id: f.get("id"), allow: list(f.get("allow")), max_hosts: parseInt(f.get("max_hosts"), 10),
      });
      if (installer) {
        box.hidden = true;
        await showInstall(c.id, f.get("reverse_dns") === "on");
      } else {
        box.className = "ok";
        box.append(
          el("p", `Crawler „${c.id}“ angelegt. Der Server hat keine --public-url, deshalb gibt es keinen Installationsbefehl. Secret für die manuelle Einrichtung (wird nur jetzt angezeigt, in agent.secret mit Rechten 600):`),
          el("pre", c.secret));
      }
      ev.target.reset();
      await refresh();
    } catch (e) {
      box.className = "error";
      box.textContent = "Abgelehnt: " + e.message;
    }
  });

  try {
    const me = await api("GET", "/api/v1/admin/me");
    installer = !!me.installer;
    showVersion(me.version);
    await showApp(me.username);
  } catch {
    showLogin();
  }
  setInterval(() => { if (!$("#app-view").hidden) refresh(); }, 20000);
});

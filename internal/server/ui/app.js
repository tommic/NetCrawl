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
  services: ["Dienste", "Welche Software in welcher Version auf welchen Geräten läuft."],
  networks: ["Netze & Crawler", "Welche Netze wie oft geprüft werden und welche Crawler das übernehmen."],
  settings: ["Benachrichtigungen", "Änderungen per Discord melden."],
  admin: ["Administration", "Export für KI-Agenten, einzelne Jobs, Job-Verlauf und Audit-Log."],
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

function message(target, text, isError) {
  const m = typeof target === "string" ? $(target) : target;
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

let serverVersion = "";

function showVersion(v) {
  serverVersion = v || "";
  $("#version").textContent = v ? "Version " + v : "";
}

// crawlerVersion shows what a crawler runs; an outdated one updates itself
// (installer with updater) or needs a rebuild/reinstall.
function crawlerVersion(c) {
  if (!c.agent_version) return el("span", "–", "muted");
  if (!c.outdated) return el("span", c.agent_version, "mono");
  const span = el("span", undefined, "nowrap");
  span.append(el("span", c.agent_version + " ", "mono"), el("span", "veraltet", "pill status-pending"));
  span.title = `Der Server hat Version ${serverVersion}. Mit dem Installationsskript eingerichtete Crawler (ab 0.11) aktualisieren sich selbst ` +
    "innerhalb weniger Minuten; ältere einmal neu installieren, Docker-Crawler mit „docker compose up -d --build“.";
  return span;
}

async function showApp(username) {
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#sidebar").hidden = false;
  document.body.classList.add("signed-in");
  $("#who").textContent = username;
  loadNetworkOptions().catch(() => { /* retried when the dialog opens */ });
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
      case "services": return renderServices();
      case "networks": renderCrawlers(crawlers); await renderNetworks(); return renderPublicURL();
      case "admin": await renderExportTokens(); await renderJobs(); return renderAudit();
      case "settings": return renderNotify(false);
    }
  } catch (e) {
    if (e.status === 401) showLogin();
  }
}

function fillNetworkSelects() {
  for (const sel of [$("#ev-network"), $("#host-network"), $("#svc-network")]) {
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

// importantBox is a checkbox for h's "important" flag. Table row and
// detail panel show the same flag, so a change updates every box of h.
function importantBox(h, onError) {
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = h.important;
  box.dataset.host = `${h.network_id}/${h.ip}`;
  box.addEventListener("change", async () => {
    try {
      await api("POST", "/api/v1/admin/hosts/important", { network_id: h.network_id, ip: h.ip, important: box.checked });
      h.important = box.checked;
      for (const b of $$(`input[data-host="${box.dataset.host}"]`)) b.checked = h.important;
    } catch (e) {
      box.checked = !box.checked;
      if (onError) onError(e);
    }
  });
  return box;
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
    const box = importantBox(h);
    box.addEventListener("click", (ev) => ev.stopPropagation());
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
    } catch (e) { message(msg, "Fehler: " + e.message, true); }
  }
  form.addEventListener("submit", (ev) => { ev.preventDefault(); setName(input.value); });
  left.append(form, msg);

  // Important flag: decides how loud a missing device is reported.
  const net = networks.find((n) => n.id === h.network_id);
  const critAfter = net ? every(net.offline_critical_minutes) : "der Schwelle des Netzes";
  const imp = el("label", undefined, "inline");
  const impBox = importantBox(h, (e) => message(msg, "Fehler: " + e.message, true));
  const impText = el("span");
  impText.append(el("strong", "Wichtiges Gerät"),
    el("span", `Fehlt das Gerät länger als ${critAfter}, meldet NetCrawl das als „Kritisch“ (einstellbar beim Netz). Sinnvoll für Router, NAS, Server oder Kameras.`, "help"));
  imp.append(impBox, impText);
  left.appendChild(imp);

  // Open ports.
  right.appendChild(el("h3", "Offene Ports"));
  if (!h.ports_scanned_at) right.appendChild(el("p", "Noch kein Portscan für diesen Host.", "hint"));
  else if (!h.ports.length) right.appendChild(el("p", "Keine offenen Ports gefunden.", "hint"));
  else {
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const hr = document.createElement("tr");
    for (const t of ["Port", "Dienst", "Offen seit"]) hr.appendChild(el("th", t));
    thead.appendChild(hr);
    const tbody = document.createElement("tbody");
    const byCat = (p) => catRank(p.service ? p.service.category : "other");
    for (const p of [...h.ports].sort((a, b) => byCat(a) - byCat(b) || a.port - b.port)) {
      const tr = document.createElement("tr");
      cell(tr, String(p.port), "mono");
      const svc = cell(tr, "");
      svc.appendChild(serviceLabel(p.service));
      if (p.service) svc.append(" ", el("span", p.service.category_label, "pill cat cat-" + p.service.category));
      cell(tr, fmt(p.first_seen));
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

// every formats an interval in minutes: "30 Min.", "2 Std.", "90 Min.".
function every(min) {
  return min % 60 === 0 ? `${min / 60} Std.` : `${min} Min.`;
}

// ---- services ----

// serviceText is "OpenSSH 9.6p1", or the protocol if the software is unknown.
function serviceText(sv) {
  if (!sv) return "";
  return sv.product ? [sv.product, sv.version].filter(Boolean).join(" ") : sv.name;
}

function serviceLabel(sv) {
  if (!sv) return el("span", "–", "muted");
  const span = el("span", serviceText(sv));
  if (sv.product) span.appendChild(el("span", " " + sv.name, "muted small"));
  span.title = [sv.extra, sv.method === "nmap" ? "erkannt mit nmap" : "erkannt über Banner/Header", sv.seen_at ? "zuletzt " + fmt(sv.seen_at) : ""]
    .filter(Boolean).join(" · ");
  return span;
}

let serviceRows = []; // one per host and port with a service
let svcGroupBy = "category"; // or "device"
let svcCategory = ""; // "" = all
const svcOpen = new Set(); // expanded software rows (category view)

// Category display order (the server assigns categories and labels).
const svcOrder = ["web", "remote", "files", "database", "mail", "network", "media", "printer", "other"];
const catRank = (c) => { const i = svcOrder.indexOf(c); return i < 0 ? svcOrder.length : i; };

async function renderServices() {
  const hosts = await api("GET", `/api/v1/admin/hosts?network_id=${$("#svc-network").value}`);
  serviceRows = [];
  for (const h of hosts) {
    for (const p of h.ports) {
      if (p.service) serviceRows.push({ h, port: p.port, sv: p.service });
    }
  }
  renderServiceTables();
}

function hostKey(h) { return h.network_id + "/" + h.ip; }
function softwareKey(sv) { return sv.category + "\0" + (sv.product || "") + "\0" + sv.name; }
const ipCompare = (a, b) => a.localeCompare(b, undefined, { numeric: true });

function renderServiceTables() {
  const q = $("#svc-filter").value.trim().toLowerCase();
  const matching = serviceRows.filter((r) => !q || [r.sv.product, r.sv.version, r.sv.name, r.sv.extra, r.sv.category_label, r.h.ip, r.h.hostname, r.h.custom_name]
    .some((v) => (v || "").toLowerCase().includes(q)));

  // Chips: one per category with services, with the number of services.
  const counts = new Map();
  const labels = new Map();
  for (const r of matching) {
    counts.set(r.sv.category, (counts.get(r.sv.category) || 0) + 1);
    labels.set(r.sv.category, r.sv.category_label);
  }
  if (svcCategory && !counts.has(svcCategory)) svcCategory = "";
  const chips = $("#svc-chips");
  chips.replaceChildren();
  const chip = (cat, text) => {
    const b = el("button", text, "chip" + (svcCategory === cat ? " active" : ""));
    b.type = "button";
    b.setAttribute("aria-pressed", String(svcCategory === cat));
    b.addEventListener("click", () => { svcCategory = cat; renderServiceTables(); });
    chips.appendChild(b);
  };
  chip("", `Alle ${matching.length}`);
  for (const c of [...counts.keys()].sort((a, b) => catRank(a) - catRank(b))) chip(c, `${labels.get(c)} ${counts.get(c)}`);

  const rows = matching.filter((r) => !svcCategory || r.sv.category === svcCategory);
  const box = $("#svc-groups");
  box.replaceChildren();
  if (!rows.length) {
    box.appendChild(el("p", serviceRows.length ? "Nichts gefunden." : "Noch keine Dienste erkannt – sie kommen mit dem nächsten Portscan.", "muted"));
    return;
  }
  if (svcGroupBy === "device") renderServicesByDevice(box, rows);
  else renderServicesByCategory(box, rows);
}

function group(title, sub) {
  const d = document.createElement("details");
  d.className = "svc-group";
  d.open = true;
  const s = document.createElement("summary");
  s.append(el("span", title, "svc-group-title"), el("span", sub, "muted small"));
  d.appendChild(s);
  return d;
}

function table(headers) {
  const t = document.createElement("table");
  const tr = document.createElement("tr");
  for (const h of headers) tr.appendChild(el("th", h));
  const thead = document.createElement("thead");
  thead.appendChild(tr);
  const tbody = document.createElement("tbody");
  t.append(thead, tbody);
  return [t, tbody];
}

// Category view: per category a table of all services. Software that
// runs more than once gets one row with an arrow; opened, its
// occurrences follow in the same columns.
function renderServicesByCategory(box, rows) {
  const cats = new Map();
  for (const r of rows) {
    if (!cats.has(r.sv.category)) cats.set(r.sv.category, { label: r.sv.category_label, software: new Map() });
    const sw = cats.get(r.sv.category).software;
    const k = softwareKey(r.sv);
    if (!sw.has(k)) sw.set(k, { sv: r.sv, rows: [] });
    sw.get(k).rows.push(r);
  }
  const versionOrder = (a, b) => (a.sv.version || "").localeCompare(b.sv.version || "", undefined, { numeric: true });
  for (const cat of [...cats.keys()].sort((a, b) => catRank(a) - catRank(b))) {
    const c = cats.get(cat);
    const list = [...c.software.entries()].sort(([, a], [, b]) =>
      !a.sv.product - !b.sv.product || (a.sv.product || a.sv.name).localeCompare(b.sv.product || b.sv.name));
    const ports = list.reduce((n, [, g]) => n + g.rows.length, 0);
    const d = group(c.label, ` · ${list.length} Software, ${ports} ${ports === 1 ? "Dienst" : "Dienste"}`);
    const [t, tbody] = table(["Software", "Version", "Dienst", "Gerät", "Port", "Erkannt"]);
    t.classList.add("svc-tree");
    for (const [k, g] of list) {
      const items = [...g.rows].sort((a, b) => versionOrder(a, b) || ipCompare(a.h.ip, b.h.ip) || a.port - b.port);
      const name = g.sv.product || "unbekannte Software";
      if (items.length === 1) {
        tbody.appendChild(serviceRow(items[0], name, false));
        continue;
      }
      const open = svcOpen.has(k);
      const tr = document.createElement("tr");
      tr.className = "clickable svc-parent";
      tr.tabIndex = 0;
      tr.setAttribute("aria-expanded", String(open));
      const sw = cell(tr, "", g.sv.product ? "strong" : "muted");
      sw.append(el("span", open ? "▾" : "▸", "caret"), document.createTextNode(name));
      const versions = new Set(items.map((r) => r.sv.version || "–"));
      cell(tr, versions.size === 1 ? [...versions][0] : `${versions.size} Versionen`, versions.size === 1 ? "mono" : "muted");
      cell(tr, [...new Set(items.map((r) => r.sv.name))].join(", "));
      const devices = new Set(items.map((r) => hostKey(r.h))).size;
      cell(tr, `${devices} ${devices === 1 ? "Gerät" : "Geräte"}`, "muted");
      cell(tr, [...new Set(items.map((r) => r.port))].sort((a, b) => a - b).join(", "), "mono");
      const last = items.map((r) => r.sv.seen_at).filter(Boolean).sort().pop();
      cell(tr, last ? ago(last) : "–");
      const toggle = () => { if (open) svcOpen.delete(k); else svcOpen.add(k); renderServiceTables(); };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } });
      tbody.appendChild(tr);
      if (open) for (const r of items) tbody.appendChild(serviceRow(r, "", true));
    }
    d.appendChild(t);
    box.appendChild(d);
  }
}

// serviceRow is one occurrence: software (empty under its parent row),
// version, protocol, device, port, last seen.
function serviceRow(r, name, child) {
  const tr = document.createElement("tr");
  if (child) tr.className = "svc-child";
  const sw = cell(tr, "", r.sv.product ? "" : "muted");
  sw.append(el("span", "", "caret"), document.createTextNode(name));
  cell(tr, r.sv.version || "–", "mono").title = r.sv.extra || "";
  cell(tr, r.sv.name);
  const dev = cell(tr, "");
  dev.append(el("span", r.h.ip, "mono"), document.createTextNode(" "), hostName(r.h));
  cell(tr, String(r.port), "mono");
  cell(tr, r.sv.seen_at ? ago(r.sv.seen_at) : "–").title = r.sv.method === "nmap" ? "erkannt mit nmap" : "erkannt über Banner/Header";
  return tr;
}

// Device view: per device its services, sorted by category.
function renderServicesByDevice(box, rows) {
  const devices = new Map();
  for (const r of rows) {
    const k = hostKey(r.h);
    if (!devices.has(k)) devices.set(k, { h: r.h, rows: [] });
    devices.get(k).rows.push(r);
  }
  for (const { h, rows: list } of [...devices.values()].sort((a, b) => ipCompare(a.h.ip, b.h.ip))) {
    const name = h.custom_name || h.hostname;
    const d = group(h.ip + (name ? " " + name : ""), ` · ${networkName(h.network_id)} · ${list.length} ${list.length === 1 ? "Dienst" : "Dienste"}`);
    const [t, tbody] = table(["Port", "Kategorie", "Software", "Version", "Dienst"]);
    for (const r of list.sort((a, b) => catRank(a.sv.category) - catRank(b.sv.category) || a.port - b.port)) {
      const tr = document.createElement("tr");
      cell(tr, String(r.port), "mono");
      cell(tr, "").appendChild(el("span", r.sv.category_label, "pill cat cat-" + r.sv.category));
      cell(tr, r.sv.product || "–", r.sv.product ? "" : "muted");
      cell(tr, r.sv.version || "–", "mono").title = r.sv.extra || "";
      cell(tr, r.sv.name);
      tbody.appendChild(tr);
    }
    d.appendChild(t);
    box.appendChild(d);
  }
}

function setupServices() {
  for (const b of $$(".seg-btn[data-group]")) {
    b.addEventListener("click", () => {
      svcGroupBy = b.dataset.group;
      for (const o of $$(".seg-btn[data-group]")) {
        o.classList.toggle("active", o === b);
        o.setAttribute("aria-pressed", String(o === b));
      }
      renderServiceTables();
    });
  }
}

// ---- network dialog (create and edit) ----

// Port presets and the defaults of a new network come from the server.
const presetLabels = {
  top100: "Top 100 – die häufigsten Ports", common: "Häufige Dienste", web: "Web-Server",
  database: "Datenbanken", tiny: "Minimal – SSH und Web", discovery: "Wie die Host-Erkennung",
};
let networkOptions = null; // { presets: name -> ports, defaults }
let networkOptionsLoad = null;

function loadNetworkOptions() {
  networkOptionsLoad ||= api("GET", "/api/v1/admin/network-options").then((o) => {
    networkOptions = { presets: Object.fromEntries(o.presets.map((p) => [p.name, p.ports])), defaults: o.defaults };
    const sel = $("#network-edit").scan_preset;
    const custom = sel.querySelector('option[value="custom"]');
    // Every server preset gets an option (known ones first, with a German
    // label), so a network using any of them never shows an empty select.
    const names = [...Object.keys(presetLabels), ...o.presets.map((p) => p.name)];
    for (const name of new Set(names)) {
      const ports = networkOptions.presets[name];
      if (ports) sel.insertBefore(new Option(`${presetLabels[name] || name} (${ports.length})`, name), custom);
    }
    const disc = networkOptions.presets.discovery || [];
    $("#discovery-ports").textContent = `${disc.length} Ports`;
    $("#discovery-ports").title = portSummary(disc);
  }).catch((e) => { networkOptionsLoad = null; throw e; });
  return networkOptionsLoad;
}

// portSummary writes ports compactly: "22, 80, 8000-8100".
function portSummary(list) {
  const out = [];
  for (let i = 0; i < list.length; i++) {
    let j = i;
    while (j + 1 < list.length && list[j + 1] === list[j] + 1) j++;
    out.push(j > i + 1 ? `${list[i]}-${list[j]}` : j === i + 1 ? `${list[i]}, ${list[j]}` : String(list[i]));
    i = j;
  }
  return out.join(", ");
}

// Number + unit pairs in the form: [field name, API key, minimum in API
// units]. The unit select is "<name>_unit" and holds the factor to the API unit.
const networkPairs = [
  ["discovery", "discovery_interval_minutes", 5], ["portscan", "portscan_interval_minutes", 15],
  ["services", "service_interval_minutes", 15],
  ["offline_critical", "offline_critical_minutes", 5], ["offline_info", "offline_info_hours", 1],
  ["offline_warn", "offline_warn_hours", 1],
];

// pairMin lets the browser check the server's minimum in the chosen unit.
function pairMin(f, [k, , min]) {
  f[k].min = String(Math.ceil(min / parseInt(f[k + "_unit"].value, 10)));
}

// setPair uses the larger unit when the value fits it evenly (1440 min -> 24 Std.).
function setPair(input, unit, value) {
  const big = parseInt(unit.options[1].value, 10);
  const useBig = value % big === 0;
  input.value = useBig ? value / big : value;
  unit.value = useBig ? String(big) : unit.options[0].value;
}

function showPresetInfo() {
  const f = $("#network-edit");
  const custom = f.scan_preset.value === "custom";
  $("#custom-ports-field").hidden = !custom;
  f.scan_ports.required = custom;
  // Only the count is shown; the list sits in a tooltip and opens on click.
  const ports = networkOptions && networkOptions.presets[f.scan_preset.value];
  $("#preset-info").hidden = custom || !ports;
  if (ports) {
    const text = portSummary(ports);
    $("#preset-count").textContent = `${ports.length} Ports – Liste anzeigen`;
    $("#preset-count").title = text;
    $("#preset-ports").textContent = text;
  }
}

let editing = null; // the network being edited, null when creating one
let networkSnapshot = ""; // form state when the dialog opened

function formState(f) {
  return JSON.stringify([...new FormData(f)]);
}

async function openNetworkDialog(n) {
  try { await loadNetworkOptions(); } catch (e) { message("#network-msg", "Fehler: " + e.message, true); return; }
  const f = $("#network-edit");
  const v = n || networkOptions.defaults;
  editing = n;
  f.reset();
  $("#network-crawler-field").hidden = !!n;
  // Disabled: left out of the form data, so a crawler list refresh while
  // editing doesn't count as a change.
  f.crawler_id.disabled = !!n;
  $("#network-title").textContent = n ? `Netz „${n.name}“ bearbeiten` : "Neues Netz";
  $("#network-edit-intro").textContent = n
    ? `Crawler: ${n.crawler_id}. Inventar und Verlauf bleiben erhalten. Änderungen gelten ab dem nächsten geplanten Scan – am Crawler ist nichts zu tun.`
    : "Nach dem Anlegen startet die erste Host-Erkennung in Kürze, danach der Portscan. Was dabei gefunden wird, gilt als Initialbestand und löst keine Meldungen aus.";
  $("#network-submit").textContent = n ? "Speichern" : "Netz anlegen";
  f.name.value = v.name || "";
  f.targets.value = v.targets.join(", ");
  f.deny.value = v.deny.join(", ");
  for (const p of networkPairs) { setPair(f[p[0]], f[p[0] + "_unit"], v[p[1]]); pairMin(f, p); }
  f.scan_preset.value = v.scan_preset;
  f.scan_ports.value = v.scan_preset === "custom" ? portSummary(v.scan_ports) : "";
  f.reverse_dns.checked = v.reverse_dns;
  f.enabled.checked = v.enabled;
  showPresetInfo();
  for (const d of f.querySelectorAll("details")) d.open = false;
  $("#network-unsaved").hidden = true;
  $("#network-edit-msg").hidden = true;
  networkSnapshot = formState(f);
  $("#network-dialog").showModal();
  $("#network-dialog").scrollTop = 0;
}

// closeNetworkDialog asks before throwing away changes.
function closeNetworkDialog() {
  if (formState($("#network-edit")) !== networkSnapshot) {
    $("#network-unsaved").hidden = false;
    $("#network-keep").focus();
    return;
  }
  $("#network-dialog").close();
}

function setupNetworkDialog() {
  const dlg = $("#network-dialog");
  const f = $("#network-edit");
  f.addEventListener("submit", saveNetwork);
  f.scan_preset.addEventListener("change", showPresetInfo);
  for (const p of networkPairs) f[p[0] + "_unit"].addEventListener("change", () => pairMin(f, p));
  f.addEventListener("input", () => { $("#network-unsaved").hidden = true; });
  $("#network-edit-close").addEventListener("click", closeNetworkDialog);
  $("#network-cancel").addEventListener("click", closeNetworkDialog);
  $("#network-keep").addEventListener("click", () => { $("#network-unsaved").hidden = true; f.name.focus(); });
  $("#network-discard").addEventListener("click", () => dlg.close());
  // Escape and a click next to the panel close it, but never silently
  // drop what was typed.
  dlg.addEventListener("cancel", (ev) => { ev.preventDefault(); closeNetworkDialog(); });
  dlg.addEventListener("click", (ev) => { if (ev.target === dlg) closeNetworkDialog(); });
  $("#network-new").addEventListener("click", () => openNetworkDialog(null));
}

async function saveNetwork(ev) {
  ev.preventDefault();
  const f = ev.target;
  const custom = f.scan_preset.value === "custom";
  const body = {
    name: f.name.value.trim(),
    targets: list(f.targets.value),
    deny: list(f.deny.value),
    discovery_ports: editing ? editing.discovery_ports : [],
    scan_preset: custom ? "" : f.scan_preset.value,
    scan_ports: custom ? list(f.scan_ports.value) : [], // the server reads "8000-8100"
    reverse_dns: f.reverse_dns.checked,
    enabled: f.enabled.checked,
  };
  for (const [k, key] of networkPairs) body[key] = parseInt(f[k].value, 10) * parseInt(f[k + "_unit"].value, 10);
  try {
    if (editing) {
      // PUT replaces all settings, so the form sends every one of them.
      await api("PUT", `/api/v1/admin/networks/${editing.id}`, body);
      $("#network-msg").hidden = true;
    } else {
      body.crawler_id = f.crawler_id.value;
      const n = await api("POST", "/api/v1/admin/networks", body);
      message("#network-msg", `Netz „${n.name}“ angelegt. Die erste Host-Erkennung startet in Kürze, danach der Portscan.`);
    }
    $("#network-dialog").close();
    await refresh();
  } catch (e) {
    message("#network-edit-msg", "Nicht gespeichert: " + e.message, true);
  }
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
    cell(tr, fmt(n.portscan_done_at) + ` (alle ${every(n.portscan_interval_minutes)}, Dienste alle ${every(n.service_interval_minutes)})`);
    cell(tr, n.enabled ? "ja" : "nein");
    const td = cell(tr, "");
    const edit = el("button", "Bearbeiten", "ghost small");
    edit.type = "button";
    edit.addEventListener("click", () => openNetworkDialog(n));
    td.appendChild(edit);
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

// ---- export tokens ----

async function renderExportTokens() {
  const tokens = await api("GET", "/api/v1/admin/export-tokens");
  const tbody = $("#export-tokens");
  tbody.replaceChildren();
  for (const t of tokens) {
    const tr = document.createElement("tr");
    cell(tr, t.name, "strong");
    cell(tr, fmt(t.created_at) + " · " + t.created_by);
    cell(tr, t.last_used_at ? fmt(t.last_used_at) : "noch nie");
    const del = el("button", "Löschen", "ghost small");
    del.type = "button";
    del.addEventListener("click", async () => {
      if (!confirm(`Lese-Token „${t.name}“ löschen? Ein Agent damit bekommt danach keinen Export mehr.`)) return;
      try {
        await api("DELETE", `/api/v1/admin/export-tokens/${t.id}`, {});
        await renderExportTokens();
      } catch (e) { message("#export-token-msg", "Fehler: " + e.message, true); }
    });
    cell(tr, "").appendChild(del);
    tbody.appendChild(tr);
  }
  if (!tokens.length) emptyRow(tbody, 4, "Noch kein Lese-Token – ohne Token geht der Export nur angemeldet im Browser.");
}

async function createExportToken(ev) {
  ev.preventDefault();
  const f = ev.target;
  try {
    const t = await api("POST", "/api/v1/admin/export-tokens", { name: f.name.value.trim() });
    const url = location.origin + "/api/v1/export.txt";
    $("#export-token-value").textContent = t.token;
    $("#export-token-curl").textContent = `curl -fsS -H 'Authorization: Bearer ${t.token}' ${url}`;
    $("#export-token-url").textContent = `${url}?token=${t.token}`;
    $("#export-token-new").hidden = false;
    $("#export-token-msg").hidden = true;
    f.reset();
    await renderExportTokens();
  } catch (e) {
    message("#export-token-msg", "Nicht erzeugt: " + e.message, true);
  }
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
    cell(tr, "").appendChild(crawlerVersion(c));
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
  if (!crawlers.length) emptyRow(tbody, 7, "Noch kein Crawler angelegt.");
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
  setupNetworkDialog();
  $("#export-token-form").addEventListener("submit", createExportToken);
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
  $("#svc-network").addEventListener("change", renderServices);
  $("#svc-filter").addEventListener("input", renderServiceTables);
  setupServices();
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

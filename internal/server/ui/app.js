"use strict";
// Admin UI for netcrawl-server. Uses the admin API with the session
// cookie; no external dependencies, all data is inserted via textContent.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
let networks = [];
let currentTab = "events";
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
  $("#tabs").hidden = true;
  $("#who").hidden = true;
  $("#logout").hidden = true;
}

async function showApp(username) {
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#tabs").hidden = false;
  $("#who").textContent = username;
  $("#who").hidden = false;
  $("#logout").hidden = false;
  await refresh();
}

function selectTab(tab) {
  if (tab === "settings" && currentTab !== "settings") renderNotify(true);
  currentTab = tab;
  for (const b of $$(".tab")) b.classList.toggle("active", b.dataset.tab === tab);
  for (const p of $$(".panel")) p.hidden = p.dataset.panel !== tab;
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
    switch (currentTab) {
      case "events": return renderEvents();
      case "hosts": return renderHosts();
      case "networks": return renderNetworks();
      case "jobs": return renderJobs();
      case "crawlers": return renderCrawlers(crawlers);
      case "audit": return renderAudit();
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

async function renderHosts() {
  const nid = $("#host-network").value;
  const hosts = await api("GET", `/api/v1/admin/hosts?network_id=${nid}`);
  const tbody = $("#hosts");
  tbody.replaceChildren();
  for (const h of hosts) {
    const tr = document.createElement("tr");
    cell(tr, networkName(h.network_id));
    cell(tr, h.ip, "mono");
    cell(tr, h.hostname || "–");
    if (h.online) cell(tr, "online", "status-completed");
    else cell(tr, "offline (" + (severityLabel[h.offline_level] || h.offline_level) + ")", "status-expired");
    cell(tr, h.ports_scanned_at ? (h.ports.map((p) => p.port).join(", ") || "keine") : "noch kein Portscan");
    cell(tr, fmt(h.first_seen));
    cell(tr, fmt(h.last_seen));
    const td = cell(tr, "");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = h.important;
    box.addEventListener("change", async () => {
      try {
        await api("POST", "/api/v1/admin/hosts/important", { network_id: h.network_id, ip: h.ip, important: box.checked });
      } catch { box.checked = !box.checked; }
    });
    td.appendChild(box);
    tbody.appendChild(tr);
  }
  if (!hosts.length) emptyRow(tbody, 8, "Noch keine Hosts – die erste Host-Erkennung läuft nach dem Anlegen eines Netzes.");
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

function renderCrawlers(crawlers) {
  const tbody = $("#crawlers");
  tbody.replaceChildren();
  for (const c of crawlers) {
    const tr = document.createElement("tr");
    cell(tr, c.id);
    if (!c.enabled) cell(tr, "deaktiviert", "status-expired");
    else if (crawlerOnline(c)) cell(tr, "online", "status-completed");
    else cell(tr, c.last_seen_at ? "offline" : "noch nie verbunden", "status-pending");
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
    box.append(
      el("h3", `Crawler „${v.crawler_id}“ installieren`),
      el("p", "Auf dem Crawler-Rechner (Debian/Ubuntu/Raspberry Pi OS mit systemd, amd64 oder arm64) als Benutzer mit sudo ausführen:"),
      pre, copy, review,
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
    await showApp(me.username);
  } catch {
    showLogin();
  }
  setInterval(() => { if (!$("#app-view").hidden) refresh(); }, 20000);
});

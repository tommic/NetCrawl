"use strict";
// Small admin UI for netcrawl-server. Uses the admin API with the session
// cookie; no external dependencies, all text is inserted via textContent.

const $ = (sel) => document.querySelector(sel);

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
  return new Date(ts).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "medium" });
}

function cell(tr, text, cls) {
  const td = document.createElement("td");
  td.textContent = text;
  if (cls) td.className = cls;
  tr.appendChild(td);
  return td;
}

function showLogin() {
  $("#login-view").hidden = false;
  $("#app-view").hidden = true;
  $("#who").hidden = true;
  $("#logout").hidden = true;
}

async function showApp(username) {
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#who").textContent = "Angemeldet als " + username;
  $("#who").hidden = false;
  $("#logout").hidden = false;
  await refresh();
}

async function refresh() {
  try {
    const [crawlers, jobs, audit] = await Promise.all([
      api("GET", "/api/v1/admin/crawlers"),
      api("GET", "/api/v1/admin/jobs?limit=50"),
      api("GET", "/api/v1/admin/audit?limit=30"),
    ]);
    renderCrawlers(crawlers);
    renderJobs(jobs);
    renderAudit(audit);
  } catch (e) {
    if (e.status === 401) showLogin();
  }
}

function renderCrawlers(list) {
  const tbody = $("#crawlers");
  const select = $("#job-form select");
  tbody.replaceChildren();
  const current = select.value;
  select.replaceChildren();
  for (const c of list) {
    const tr = document.createElement("tr");
    cell(tr, c.id);
    cell(tr, c.allow.join(", "));
    cell(tr, String(c.max_hosts));
    cell(tr, fmt(c.last_seen_at));
    tbody.appendChild(tr);
    const opt = document.createElement("option");
    opt.value = opt.textContent = c.id;
    select.appendChild(opt);
  }
  if (current) select.value = current;
  if (!list.length) {
    const tr = document.createElement("tr");
    cell(tr, "Noch kein Crawler registriert.").colSpan = 4;
    tbody.appendChild(tr);
  }
}

function jobStatus(j) {
  if (j.expired) return ["abgelaufen", "status-expired"];
  return ({ pending: ["wartet", "status-pending"], delivered: ["beim Crawler", "status-delivered"], completed: ["fertig", "status-completed"] })[j.status] || [j.status, ""];
}

function renderJobs(list) {
  const tbody = $("#jobs");
  tbody.replaceChildren();
  for (const j of list) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    const [label, cls] = jobStatus(j);
    cell(tr, fmt(j.created_at));
    cell(tr, j.crawler_id);
    cell(tr, label, cls);
    cell(tr, j.targets.join(", "));
    cell(tr, j.ports.join(", "));
    cell(tr, fmt(j.expires_at));
    tr.addEventListener("click", () => showJob(j.id));
    tbody.appendChild(tr);
  }
  if (!list.length) {
    const tr = document.createElement("tr");
    cell(tr, "Noch keine Jobs.").colSpan = 6;
    tbody.appendChild(tr);
  }
}

async function showJob(id) {
  const box = $("#job-detail");
  box.hidden = false;
  box.replaceChildren();
  let j;
  try { j = await api("GET", "/api/v1/admin/jobs/" + encodeURIComponent(id)); }
  catch (e) { box.textContent = "Fehler: " + e.message; return; }
  const h = document.createElement("h2");
  h.textContent = "Job " + j.id;
  box.appendChild(h);
  if (!j.result) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = j.status === "completed" ? "Kein Ergebnis gespeichert." : "Noch kein Ergebnis – der Crawler fragt alle 60 Sekunden nach.";
    box.appendChild(p);
    return;
  }
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>Netz</th><th>Host</th><th>Offene Ports</th></tr></thead>";
  const tbody = document.createElement("tbody");
  let rows = 0;
  for (const net of j.result.networks || []) {
    for (const [ip, host] of Object.entries(net.hosts || {})) {
      const tr = document.createElement("tr");
      cell(tr, net.network);
      cell(tr, ip);
      cell(tr, (host.ports || []).join(", "));
      tbody.appendChild(tr);
      rows++;
    }
  }
  if (!rows) {
    const tr = document.createElement("tr");
    cell(tr, "Keine offenen Ports gefunden.").colSpan = 3;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  box.appendChild(table);
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(j.result, null, 2);
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Rohdaten (JSON)";
  details.append(summary, pre);
  box.appendChild(details);
}

function renderAudit(list) {
  const tbody = $("#audit");
  tbody.replaceChildren();
  for (const e of list) {
    const tr = document.createElement("tr");
    cell(tr, fmt(e.at));
    cell(tr, e.actor);
    cell(tr, e.action);
    cell(tr, e.details && e.details !== null ? JSON.stringify(e.details) : "");
    tbody.appendChild(tr);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const err = $("#login-error");
    err.hidden = true;
    try {
      const me = await api("POST", "/api/v1/admin/login", { username: f.get("username"), password: f.get("password") });
      ev.target.reset();
      await showApp(me.username);
    } catch (e) {
      err.textContent = e.status === 429 ? "Zu viele Fehlversuche, bitte später erneut versuchen." : "Benutzer oder Passwort falsch.";
      err.hidden = false;
    }
  });

  $("#logout").addEventListener("click", async () => {
    try { await api("POST", "/api/v1/admin/logout"); } catch {}
    showLogin();
  });

  $("#refresh").addEventListener("click", refresh);

  $("#job-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const msg = $("#job-msg");
    const ports = String(f.get("ports")).split(",").map((p) => parseInt(p.trim(), 10)).filter((p) => !Number.isNaN(p));
    try {
      const j = await api("POST", "/api/v1/admin/jobs", {
        crawler_id: f.get("crawler_id"),
        targets: String(f.get("target")).split(",").map((t) => t.trim()).filter(Boolean),
        ports,
        ttl_seconds: parseInt(f.get("ttl"), 10) * 60,
      });
      msg.className = "";
      msg.textContent = "Job angelegt. Der Crawler holt ihn beim nächsten Abfragen ab (alle 60 s).";
      msg.hidden = false;
      await refresh();
      showJob(j.id);
    } catch (e) {
      msg.className = "error";
      msg.textContent = "Abgelehnt: " + e.message;
      msg.hidden = false;
    }
  });

  try {
    const me = await api("GET", "/api/v1/admin/me");
    await showApp(me.username);
  } catch {
    showLogin();
  }
  setInterval(() => { if (!$("#app-view").hidden) refresh(); }, 15000);
});

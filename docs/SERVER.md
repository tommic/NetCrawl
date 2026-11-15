# Server und Crawler betreiben

`netcrawl-server` verwaltet Crawler, Netze, Inventar und Ereignisse in PostgreSQL. `netcrawl-agent` (der Crawler) holt Jobs ab, prüft sie gegen seine lokale Freigabe, scannt und meldet signierte Ergebnisse zurück. Protokoll: [`PROTOCOL.md`](PROTOCOL.md).

## So funktioniert es

```text
Netz anlegen (Bereich, Deny-Liste, Zeitplan)
        │
        ▼
Scheduler ── alle 30 Min. ──► Host-Erkennung  ──► Crawler ──► wer ist online?
          └─ täglich ───────► Portscan (Top 100, nur Hosts, die online sind)
        │
        ▼
Inventar (IP, Hostname, offene Ports, zuerst/zuletzt gesehen)
        │
        ▼
Ereignisse (Weboberfläche, CLI, JSONL-Log)
```

- **Host-Erkennung:** Ein Host gilt als online, wenn er auf mindestens einem Erkennungs-Port antwortet – auch ein „Verbindung abgelehnt“ zählt, denn das beweist, dass er da ist. Dafür sind keine Root-Rechte nötig. Geräte, die alle Ports stumm verwerfen, sieht diese Erkennung nicht.
- **Initialbestand:** Der erste Lauf eines Netzes erzeugt den Bestand und markiert diese Meldungen als „Initialbestand“ (standardmäßig ausgeblendet). Danach werden nur echte Änderungen gemeldet.
- **Ereignisse:**

| Ereignis | Stufe |
|---|---|
| neuer Host | Info |
| Host seit 24 h nicht gesehen | Info |
| Host seit 7 Tagen nicht gesehen | Warnung, **kritisch** bei als „wichtig“ markierten Geräten |
| Host wieder erreichbar | Info |
| Hostname geändert | Info |
| Port neu offen | **Warnung** |
| Port nicht mehr offen | Info |

Die Schwellen sind pro Netz einstellbar. „Nicht gesehen“ wird an den tatsächlich gelaufenen Erkennungen gemessen: Fällt der Crawler aus, werden nicht plötzlich alle Hosts als verschwunden gemeldet.

## Freigabe: was ein Crawler scannen darf

Ein Netz wird nur gescannt, wenn es an **zwei Stellen** freigegeben ist:

| Wo | Was |
|---|---|
| **Server** (Crawler-Registrierung) | `--allow` und `--max-hosts`: Der Server legt keine Jobs außerhalb davon an. |
| **Crawler** (`agent.json`, `limits`) | `allow` und `max_hosts`: harte lokale Grenze. Jobs außerhalb werden abgelehnt, bevor eine Verbindung aufgebaut wird – auch wenn ein (kompromittierter) Server sie schickt. |

Erlaubt sind private Bereiche (RFC 1918, Loopback, Link-Local, CGNAT). Öffentliche Bereiche verweigern Server und Crawler; der Crawler akzeptiert sie nur mit `"allow_public_ranges": true` in seiner lokalen Konfiguration. `max_hosts` muss die Größe des Netzes abdecken (ein `/24` hat 256 Adressen).

## Testumgebung in 1 Minute

Voraussetzung: Docker unter Linux (alle Container nutzen das Host-Netz).

```bash
cd deploy/testenv
./testenv.sh up       # Datenbank, Server, Testziel, Crawler und ein Testnetz einrichten
./testenv.sh scan     # Host-Erkennung und Portscan sofort ausführen
./testenv.sh events   # Änderungen anzeigen
./testenv.sh hosts    # Inventar anzeigen
./testenv.sh login    # Zugangsdaten für Browser und API
./testenv.sh down     # alles entfernen (inkl. Datenbank)
```

Das Testnetz umfasst `127.0.0.1`–`127.0.0.4`, `127.0.0.4` steht auf der Deny-Liste. Ausprobieren: auf `127.0.0.1:18082` einen Dienst starten (z. B. `python3 -m http.server 18082 --bind 127.0.0.1`), `./testenv.sh scan` – es erscheint „Port 18082 neu offen“. Dienst beenden, erneut scannen – „Port 18082 nicht mehr offen“.

Im Browser unter `http://127.0.0.1:8080` anmelden. Ports: Server `8080`, PostgreSQL `55432`, Testziel `18081`; änderbar beim ersten `up` mit `NETCRAWL_PORT`, `NETCRAWL_DB_PORT`, `NETCRAWL_TARGET_PORT`. Das Ereignislog liegt in `deploy/testenv/data/events/`.

## Weboberfläche

Unter `/`: **Ereignisse** (mit Zähler für Warnungen der letzten 24 h), **Inventar** (Hosts mit Status, offenen Ports, „wichtig“-Markierung), **Netze** (anlegen, „Erkennung jetzt“, „Portscan jetzt“), **Jobs**, **Crawler** (registrieren, Secret wird einmalig angezeigt) und **Audit-Log**. Die Oberfläche nutzt nur die Admin-API, lädt nichts von außen und läuft unter einer strikten Content-Security-Policy. `serve --embeddable` erlaubt die Anzeige in fremden Frames und ist **nur für Testumgebungen** gedacht.

## Einrichtung für ein echtes Netz

### 1. Server starten (Proxmox-LXC mit Docker)

```bash
cd deploy
cp .env.example .env          # NETCRAWL_DB_PASSWORD setzen, z. B. openssl rand -base64 32
docker compose up -d --build
curl http://127.0.0.1:8080/healthz
```

- PostgreSQL läuft mit persistentem Volume `db-data`; der Server spielt Migrationen beim Start ein und ist nur auf `127.0.0.1:8080` erreichbar.
- Ereignislog als JSONL: `serve --event-log-dir /pfad` (eine Datei pro Tag, 180 Tage aufbewahrt).
- Für Crawler auf anderen Rechnern einen HTTPS-Reverse-Proxy davorsetzen (oder `serve --tls-cert … --tls-key …`). Der Crawler verweigert unverschlüsseltes HTTP zu nicht-lokalen Servern.

### 2. Admin-Passwort setzen

```bash
read -rs PW && printf '%s\n' "$PW" | docker compose run --rm -T server admin set-password --username admin; unset PW
```

Mindestens 12 Zeichen. Nach 5 Fehlversuchen innerhalb von 15 Minuten wird die IP 15 Minuten gesperrt.

### 3. Crawler registrieren

```bash
docker compose run --rm server crawler add --id lan-1 --allow 192.168.1.0/24 --max-hosts 256
```

Das **Secret wird nur einmal angezeigt**. Auf dem Crawler-Rechner:

```bash
printf '%s\n' '<SECRET>' > agent.secret && chmod 600 agent.secret
cp configs/agent.example.json agent.json
```

In `agent.json` `crawler_id`, `server_url` und unter `limits` **dieselbe Freigabe** eintragen:

```json
"limits": { "allow": ["192.168.1.0/24"], "max_hosts": 256 },
"reverse_dns": true
```

`reverse_dns` erlaubt Hostnamen-Abfragen (PTR) über den DNS-Server des Crawler-Rechners.

### 4. Netz anlegen

```bash
docker compose run --rm server network add --crawler lan-1 --name Heimnetz \
  --target 192.168.1.0/24 --deny 192.168.1.1,192.168.1.250-192.168.1.254
```

Standards: Erkennung alle 30 Minuten (Ports: 22, 53, 80, 135, 139, 443, 445, 3389, 5000, 8080, 8443, 62078), Portscan alle 24 Stunden (Top 100), Info nach 24 h, Warnung nach 7 Tagen. Ändern mit `--discovery-interval`, `--portscan-interval`, `--scan-preset`, `--scan-ports`, `--discovery-ports`, `--offline-info`, `--offline-warn`. Oder in der Weboberfläche unter „Netze“.

### 5. Crawler starten

```bash
./netcrawl-agent --config agent.json          # dauerhaft, fragt alle interval_seconds nach Jobs
./netcrawl-agent --config agent.json --once   # einmal abfragen
```

Vor jedem Netzwerkzugriff prüft der Crawler: gültige Konfiguration inkl. `crawler_id`, `polling.interval_seconds >= 60`, gültige Freigabe (private Bereiche, Hostlimit), kein bereits laufender Crawl (Lock-Datei). Schlägt etwas fehl, beendet er sich ohne Request. Exit-Codes bei `--once`: `0` ok, `1` Fehler, `2` Job lokal abgelehnt.

### 6. Ergebnisse ansehen

```bash
docker compose run --rm server hosts
docker compose run --rm server events
docker compose run --rm server network list
docker compose run --rm server network scan --id 1 --kind discovery   # sofort erkennen
```

## Admin-API

| Methode | Pfad | Zweck |
|---|---|---|
| `POST` | `/api/v1/admin/login`, `/logout` | An-/Abmelden (Session-Cookie) |
| `GET` | `/api/v1/admin/me` | aktueller Benutzer |
| `GET`/`POST` | `/api/v1/admin/crawlers` | Crawler auflisten / registrieren (Secret einmalig in der Antwort) |
| `GET`/`POST` | `/api/v1/admin/networks` | Netze auflisten / anlegen |
| `PUT` | `/api/v1/admin/networks/{id}` | Netz ändern (z. B. `"enabled": false`) |
| `POST` | `/api/v1/admin/networks/{id}/scan` | `{"kind": "discovery"}` oder `{"kind": "ports"}` sofort |
| `GET` | `/api/v1/admin/hosts?network_id=` | Inventar |
| `POST` | `/api/v1/admin/hosts/important` | `{"network_id", "ip", "important"}` |
| `GET` | `/api/v1/admin/events?network_id=&ip=&baseline=1&limit=` | Ereignisse, neueste zuerst |
| `GET`/`POST` | `/api/v1/admin/jobs` | Jobs auflisten / einzelnen Job anlegen |
| `GET` | `/api/v1/admin/jobs/{id}` | Job mit Ergebnis |
| `GET` | `/api/v1/admin/audit` | Audit-Log |

Schreibende Requests mit Session-Cookie müssen `Content-Type: application/json` senden (Schutz gegen Cross-Site-Requests, zusätzlich zu `SameSite=Strict`).

## Sicherheitshinweise

- Crawler-Secrets und Result-Tokens liegen im Klartext in der Datenbank, weil der Server sie zur HMAC-Prüfung braucht. Datenbank-Zugriff und Backups entsprechend schützen.
- Admin-Passwörter werden mit bcrypt gespeichert, Session-Tokens nur als SHA-256.
- Anmeldungen, Registrierungen, Netz- und Job-Anlagen, Auslieferungen, angenommene/abgelehnte Ergebnisse und Fehler des Schedulers stehen im Audit-Log.
- Vor dem ersten echten Scan: Umfang, Deny-Liste, Zeitfenster und Abbruchweg festlegen (siehe Projektnotiz „Start – Netzwerk-Inventarisierung & Scan-Vorbereitung“).

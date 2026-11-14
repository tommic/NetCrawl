# Server und Crawler betreiben

`netcrawl-server` verwaltet Crawler, Jobs und Ergebnisse in PostgreSQL. `netcrawl-agent` (der Crawler) holt Jobs ab, prüft sie lokal, scannt und meldet signierte Ergebnisse zurück. Protokoll: [`PROTOCOL.md`](PROTOCOL.md).

> **Stand M1 – nur Loopback-Pilot.** Server und Crawler akzeptieren ausschließlich das Ziel `127.0.0.1/32` mit `max_hosts: 1`. Echte Netze folgen erst nach dokumentierter Freigabe.

## Aufteilung der Konfiguration

| Wo | Was |
|---|---|
| **Server** | Crawler registrieren (ID, serverseitige Allowlist, Hostlimit), Jobs anlegen (Ziele, Ports, TTL), Ergebnisse, Audit-Log |
| **Crawler** (`agent.json`) | eigene ID, Server-URL, Secret, Abfrageintervall, **lokale Allowlist und Hostlimit** (harte Grenze, die der Server nicht überschreiben kann), Lock-Datei |

## Testumgebung in 1 Minute

Voraussetzung: Docker (Linux, weil der Crawler `network_mode: host` nutzt).

```bash
cd deploy/testenv
./testenv.sh up       # Datenbank, Server, Testziel und Crawler starten, Admin + Crawler einrichten
./testenv.sh scan     # Test-Job anlegen und sofort scannen
./testenv.sh login    # Zugangsdaten für Browser und API anzeigen
./testenv.sh down     # alles wieder entfernen (inkl. Datenbank)
```

Im Browser unter `http://127.0.0.1:8080` anmelden (Benutzer `admin`, Passwort zeigt `./testenv.sh login`). Ports lassen sich mit `NETCRAWL_PORT` und `NETCRAWL_TARGET_PORT` beim ersten `up` ändern. Das Testziel ist ein kleiner Webserver auf `127.0.0.1:18081`.

## Weboberfläche

Unter `/` liefert der Server eine kleine Admin-Oberfläche aus: Anmelden, Jobs anlegen, Jobs mit Ergebnis, Crawler und Audit-Log. Sie nutzt nur die Admin-API, lädt nichts von außen und läuft unter einer strikten Content-Security-Policy. `serve --embeddable` erlaubt die Anzeige in einem fremden Frame (z. B. einer Vorschau). Das ist **nur für Testumgebungen** gedacht.

## 1. Server starten (Proxmox-LXC mit Docker)

```bash
cd deploy
cp .env.example .env          # NETCRAWL_DB_PASSWORD setzen, z. B. openssl rand -base64 32
docker compose up -d --build
curl http://127.0.0.1:8080/healthz
```

- PostgreSQL läuft mit persistentem Volume `db-data`.
- Der Server spielt beim Start die Datenbank-Migrationen ein und ist nur auf `127.0.0.1:8080` erreichbar.
- Für Crawler auf anderen Rechnern einen HTTPS-Reverse-Proxy davorsetzen (oder `serve --tls-cert … --tls-key …`) und `--secure-cookies` setzen. Der Crawler verweigert unverschlüsseltes HTTP zu nicht-lokalen Servern.

Ohne Docker:

```bash
make build
export NETCRAWL_DATABASE_URL='postgres://netcrawl:…@127.0.0.1:5432/netcrawl?sslmode=disable'
./netcrawl-server serve --listen 127.0.0.1:8080
```

## 2. Admin-Passwort setzen

```bash
read -rs PW && printf '%s\n' "$PW" | docker compose run --rm -T server admin set-password --username admin; unset PW
```

Mindestens 12 Zeichen. Login über die API: `POST /api/v1/admin/login` mit `{"username": "...", "password": "..."}`; die Sitzung (12 h) läuft über ein HttpOnly-Cookie. Nach 5 Fehlversuchen innerhalb von 15 Minuten wird die IP 15 Minuten gesperrt.

## 3. Crawler registrieren

```bash
docker compose run --rm server crawler add --id pilot-1 --allow 127.0.0.1/32 --max-hosts 1
```

Das ausgegebene **Secret wird nur einmal angezeigt**. Auf dem Crawler-Rechner:

```bash
printf '%s\n' '<SECRET>' > agent.secret
chmod 600 agent.secret
cp configs/agent.example.json agent.json   # crawler_id und server_url anpassen
```

Der Crawler startet nicht, wenn die Secret-Datei für Gruppe oder andere lesbar ist. Alternativ kann das Secret über die Umgebungsvariable `NETCRAWL_AGENT_SECRET` kommen (dann `secret_file` leer lassen).

## 4. Job anlegen

```bash
docker compose run --rm server job create --crawler pilot-1 --target 127.0.0.1/32 --ports 22,80,443 --ttl 5m
```

oder per API (`POST /api/v1/admin/jobs` mit Session-Cookie):

```json
{"crawler_id": "pilot-1", "targets": ["127.0.0.1/32"], "ports": [22, 80, 443], "ttl_seconds": 300}
```

## 5. Crawler starten

```bash
./netcrawl-agent --config agent.json --once   # einmal abfragen
./netcrawl-agent --config agent.json          # dauerhaft, alle interval_seconds
```

Vor jedem Netzwerkzugriff prüft der Crawler:

1. gültige Konfiguration inkl. `crawler_id`,
2. `polling.interval_seconds >= 60`,
3. lokale Allowlist genau `127.0.0.1/32` und Hostlimit `1`,
4. kein bereits laufender Crawl (Lock-Datei).

Schlägt eine Prüfung fehl, beendet er sich ohne Request. Exit-Codes bei `--once`: `0` ok, `1` Fehler, `2` Job lokal abgelehnt.

## 6. Ergebnisse ansehen

```bash
docker compose run --rm server job list
docker compose run --rm server job show <JOB_ID>
```

API: `GET /api/v1/admin/jobs`, `GET /api/v1/admin/jobs/{id}` (inkl. Ergebnis), `GET /api/v1/admin/crawlers`, `GET /api/v1/admin/audit`.

## Admin-API

| Methode | Pfad | Zweck |
|---|---|---|
| `POST` | `/api/v1/admin/login` | Anmelden (setzt Session-Cookie) |
| `POST` | `/api/v1/admin/logout` | Abmelden |
| `GET` | `/api/v1/admin/me` | aktueller Benutzer |
| `GET`/`POST` | `/api/v1/admin/crawlers` | Crawler auflisten / registrieren (Antwort enthält das Secret einmalig) |
| `GET`/`POST` | `/api/v1/admin/jobs` | Jobs auflisten / anlegen |
| `GET` | `/api/v1/admin/jobs/{id}` | Job mit Ergebnis |
| `GET` | `/api/v1/admin/audit` | Audit-Log |

Schreibende Requests mit Session-Cookie müssen `Content-Type: application/json` senden (Schutz gegen Cross-Site-Requests, zusätzlich zu `SameSite=Strict`).

## Sicherheitshinweise

- Crawler-Secrets und Result-Tokens liegen im Klartext in der Datenbank, weil der Server sie zur HMAC-Prüfung braucht. Datenbank-Zugriff und Backups entsprechend schützen.
- Admin-Passwörter werden mit bcrypt gespeichert, Session-Tokens nur als SHA-256.
- Alle Anmeldungen, Registrierungen, Job-Anlagen, Auslieferungen sowie angenommene und abgelehnte Ergebnisse stehen im Audit-Log.

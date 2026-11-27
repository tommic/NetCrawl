# Server und Crawler betreiben

`netcrawl-server` verwaltet Crawler, Netze, Inventar und Ereignisse in PostgreSQL. `netcrawl-agent` (der Crawler) holt Jobs ab, prüft sie gegen seine lokale Freigabe, scannt und meldet signierte Ergebnisse zurück. Protokoll: [`PROTOCOL.md`](PROTOCOL.md).

## So funktioniert es

```text
Netz anlegen (Bereich, Deny-Liste, Zeitplan)
        │
        ▼
Scheduler ── alle 30 Min. ──► Host-Erkennung  ──► Crawler ──► wer ist online?
          └─ täglich ───────► Portscan (Top 100, nur Hosts, die online sind)
Neuer Host erkannt ──────────► sofort Portscan nur für diesen Host
        │
        ▼
Inventar (IP, Hostname, offene Ports, zuerst/zuletzt gesehen)
        │
        ▼
Ereignisse (Weboberfläche, CLI, JSONL-Log, Discord)
```

- **Host-Erkennung:** Ein Host gilt als online, wenn er auf mindestens einem Erkennungs-Port antwortet – auch ein „Verbindung abgelehnt“ zählt, denn das beweist, dass er da ist. Dafür sind keine Root-Rechte nötig. Geräte, die alle Ports stumm verwerfen, sieht diese Erkennung nicht.
- **Initialbestand:** Der erste Lauf eines Netzes erzeugt den Bestand und markiert diese Meldungen als „Initialbestand“ (standardmäßig ausgeblendet). Danach werden nur echte Änderungen gemeldet.
- **Ereignisse:**

| Ereignis | Stufe |
|---|---|
| neuer Host | Info |
| als „wichtig“ markiertes Gerät seit 60 Min. nicht gesehen | **Kritisch** |
| Host seit 24 h nicht gesehen | Info |
| Host seit 7 Tagen nicht gesehen | Warnung |
| Host wieder erreichbar | Info |
| Hostname geändert | Info |
| Port neu offen | **Warnung** |
| Port nicht mehr offen | Info |

Die Schwellen sind pro Netz einstellbar.

### Benachrichtigung per Discord

Unter **Benachrichtigungen** eine Discord-Webhook-URL eintragen (Discord: Servereinstellungen → Integrationen → Webhooks → „Neuer Webhook“ → „Webhook-URL kopieren“), die Stufe wählen und aktivieren. „Testnachricht senden“ prüft die Verbindung.

- **Melden ab:** *Info* (alle Änderungen inkl. neuer Hosts), *Warnung* (Standard: neu offene Ports, Hosts 7 Tage weg) oder *Kritisch*.
- Gesendet werden nur Änderungen ab dem Speichern, nie der Initialbestand. Der Scheduler prüft alle 30 Sekunden und bündelt bis zu 25 Änderungen in einer Nachricht.
- Ist Discord nicht erreichbar, bleiben die Änderungen vorgemerkt; neuer Versuch nach 1 Minute, danach mit wachsendem Abstand bis 15 Minuten. Der letzte Fehler steht auf der Seite.
- Die Webhook-URL ist ein Zugangsschlüssel. Sie wird nur in der Datenbank gespeichert und nie wieder angezeigt (auch nicht im Audit-Log). Erlaubt sind nur Adressen von `discord.com`.
- Hostnamen stammen aus DNS-Antworten, die Geräte im Netz selbst festlegen können. Sie werden in der Nachricht maskiert und können niemanden erwähnen (`@everyone` o. Ä.).
- Der Server braucht dafür ausgehenden HTTPS-Zugang zu `discord.com`. „Nicht gesehen“ wird an den tatsächlich gelaufenen Erkennungen gemessen: Fällt der Crawler aus, werden nicht plötzlich alle Hosts als verschwunden gemeldet.

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

Im Browser unter `http://127.0.0.1:8080` anmelden. Unter „Crawler“ lässt sich auch der Installationsbefehl ausprobieren (in der Testumgebung über `http` auf Loopback); er installiert einen echten systemd-Dienst auf dem Rechner, der nur `127.0.0.x` scannen darf. Ports: Server `8080`, PostgreSQL `55432`, Testziel `18081`; änderbar beim ersten `up` mit `NETCRAWL_PORT`, `NETCRAWL_DB_PORT`, `NETCRAWL_TARGET_PORT`. Das Ereignislog liegt in `deploy/testenv/data/events/`.

## Weboberfläche

Unter `/` (Menü links, auf dem Handy oben): **Übersicht** (Hosts online, neue Hosts und Warnungen der letzten 24 h, Crawler offline, neueste Ereignisse, Netzwerk-Status, „Erkennung jetzt“/„Portscan jetzt“ für alle Netze), **Ereignisse** (mit Zähler für Warnungen der letzten 24 h), **Inventar** (Hosts mit Status, offenen Ports, „wichtig“-Markierung; Klick öffnet Details, eigenen Namen und den Schalter „Wichtiges Gerät“), **Netze & Crawler** (Netze anlegen und bearbeiten in einem Panel mit Erklärungen zu jeder Einstellung, Crawler anlegen mit Installationsbefehl, Status online/offline, Freigabe ändern, deaktivieren), **Benachrichtigungen** (Discord) und **Administration** (einzelne Jobs, Job-Verlauf, Audit-Log). Dunkles Design, mit dem Schalter unten im Menü auf hell umschaltbar (merkt sich der Browser). Unten im Menü steht die Server-Version. Auf sehr breiten Bildschirmen bleibt die Oberfläche bei 1760 px Breite zentriert. Die Oberfläche nutzt nur die Admin-API, lädt nichts von außen und läuft unter einer strikten Content-Security-Policy. `serve --embeddable` erlaubt die Anzeige in fremden Frames und ist **nur für Testumgebungen** gedacht.

## Einrichtung für ein echtes Netz

### 1. Server starten (z. B. Proxmox-LXC mit Docker)

```bash
cd deploy
cp .env.example .env
```

In `.env` setzen:

- `NETCRAWL_DB_PASSWORD`: langes Zufallspasswort, z. B. aus `openssl rand -base64 32`
- `NETCRAWL_PUBLIC_URL` (optional): wie die Crawler den Server erreichen, z. B. `https://192.168.1.5:8443` (IP des Servers) oder `https://netcrawl.example.org`. Ohne diese Einstellung schlägt die Weboberfläche unter **Crawler** die Adresse vor, unter der sie gerade geöffnet ist; ein Klick auf „Übernehmen“ speichert sie.

```bash
docker compose up -d --build
docker compose logs server | tail -3
```

- Der Server spricht HTTPS auf Port `8443`. Beim ersten Start erzeugt er ein **selbstsigniertes Zertifikat** (gespeichert im Volume `server-data`). Crawler vertrauen genau dessen Schlüssel (Pinning), eine Zertifizierungsstelle ist nicht nötig. Der Browser warnt beim ersten Aufruf einmal.
- Das Log zeigt `crawler installer enabled` mit dem Fingerprint (`tls_pin`).
- PostgreSQL läuft mit persistentem Volume `db-data`; Migrationen werden beim Start eingespielt.
- Nur aus einem Netz erreichbar machen: `NETCRAWL_BIND=192.168.1.5` (Adresse des Servers) in `.env`.

**Mit Domain und eigenem Zertifikat** (z. B. Let's Encrypt): `NETCRAWL_PUBLIC_URL=https://netcrawl.example.org` und das Zertifikat per `--tls-cert`/`--tls-key` statt `--tls-self-signed` übergeben. Ein von einer CA ausgestelltes Zertifikat wird nicht gepinnt, Crawler prüfen es normal. Hinter einem Reverse-Proxy: Server ohne TLS auf `127.0.0.1` lauschen lassen, `--secure-cookies` setzen, `NETCRAWL_PUBLIC_URL` auf die Proxy-Adresse.

### 2. Admin-Passwort setzen

```bash
read -rs PW && printf '%s\n' "$PW" | docker compose run --rm -T server admin set-password --username admin; unset PW
```

Mindestens 12 Zeichen. Nach 5 Fehlversuchen innerhalb von 15 Minuten wird die IP 15 Minuten gesperrt. Anmelden unter `https://<Server-IP>:8443`.

### 3. Crawler anlegen und installieren

In der Weboberfläche unter **Crawler → Crawler anlegen**: ID (z. B. `lan-1`), Freigabe (z. B. `192.168.1.0/24`), max. Hosts (`256` für ein `/24`), ob Hostnamen abgefragt werden dürfen. Danach zeigt die Oberfläche einen Einzeiler:

```bash
curl -fsSL -k --pinnedpubkey 'sha256//…' 'https://192.168.1.5:8443/install/…' | sudo sh
```

Auf dem Crawler-Rechner ausführen (Debian/Ubuntu, Raspberry Pi OS, Proxmox-LXC; mit systemd; amd64 oder arm64). Das Skript:

1. lädt `netcrawl-agent` vom eigenen Server und prüft die Prüfsumme,
2. legt den Systembenutzer `netcrawl`, `/etc/netcrawl-agent/` und `/var/lib/netcrawl-agent/` an,
3. löst den Einmal-Code ein: Der Crawler erhält ein **neues** Secret, die Freigabe wird **fest** in die lokale `agent.json` geschrieben,
4. richtet den abgesicherten Dienst `netcrawl-agent.service` ein und startet ihn.

Nach spätestens einer Minute steht der Crawler in der Oberfläche auf „online“.

- `-k --pinnedpubkey`: curl prüft statt einer CA exakt den Schlüssel des Servers. Ein anderer Server (z. B. ein Angreifer im Netz) wird abgewiesen, bevor Daten fließen.
- Der Code gilt **einmal** und **30 Minuten**. Ein neuer Code macht den vorherigen ungültig. Wer `curl | sh` nicht mag: In der Oberfläche unter „Skript erst ansehen, dann ausführen“ steht die Variante zum Herunterladen und Prüfen.
- Die lokale Freigabe kann der Server danach nicht mehr ausweiten (siehe „Freigabe ändern“).
- Logs: `journalctl -u netcrawl-agent -f`. Deinstallation: `curl -fsS -k --pinnedpubkey 'sha256//…' https://<Server>:8443/install/uninstall | sudo sh`.
- In unprivilegierten LXC-Containern ohne „nesting“ kann systemd die Dateisystem-Sandbox nicht einrichten. Das Skript erkennt das und startet den Dienst dann mit reduzierter Absicherung (weiterhin eigener Benutzer, keine Capabilities).

Ohne Weboberfläche:

```bash
docker compose run --rm server crawler add --id lan-1 --allow 192.168.1.0/24 --max-hosts 256
docker compose run --rm server crawler install --id lan-1 --reverse-dns
```

**Freigabe ändern** (z. B. weiteres Netz): unter **Crawler** auf „Freigabe ändern“. Danach muss der Crawler **neu installiert** werden – mit Absicht: Die Freigabe ist auf dem Crawler-Rechner fest hinterlegt, damit ein kompromittierter Server die Grenzen eines Crawlers nicht aus der Ferne erweitern kann. Ablauf:

1. Neue Freigabe eintragen. Alle Netze des Crawlers müssen hineinpassen, sonst wird die Änderung abgelehnt.
2. Offene Jobs verfallen; der Crawler steht auf „Neuinstallation nötig“ und scannt bis dahin nur innerhalb seiner alten Freigabe.
3. Den angezeigten Installationsbefehl auf dem Crawler-Rechner ausführen. Das Skript erkennt die vorhandene Installation und ersetzt sie vollständig (Dienst, Konfiguration, Secret, Lock). Netze, Inventar und Verlauf bleiben erhalten.

Läuft der Crawler danach auf einem **anderen** Rechner, auf dem alten aufräumen: `curl -fsS -k --pinnedpubkey 'sha256//…' https://<Server>:8443/install/uninstall | sudo sh` (steht auch in der Oberfläche unter „Alte Installation entfernen“). Ein alter Crawler, dessen Secret ersetzt wurde, beendet sich ohnehin nach drei abgelehnten Abfragen (Exit-Code 3, systemd startet ihn nicht neu).

**Crawler sperren** (z. B. Gerät verloren): in der Oberfläche „Deaktivieren“ oder `crawler disable --id lan-1`. Er bekommt keine Jobs mehr, seine Abfragen und Ergebnisse werden abgelehnt; nach drei abgelehnten Abfragen beendet sich der Crawler-Dienst. Nach dem Entsperren auf dem Crawler-Rechner `sudo systemctl start netcrawl-agent`.

### 4. Netz anlegen

```bash
docker compose run --rm server network add --crawler lan-1 --name Heimnetz \
  --target 192.168.1.0/24 --deny 192.168.1.1,192.168.1.250-192.168.1.254
```

Standards: Erkennung alle 30 Minuten (Ports: 22, 53, 80, 135, 139, 443, 445, 3389, 5000, 8080, 8443, 62078), Portscan alle 24 Stunden (Top 100), Info nach 24 h, Warnung nach 7 Tagen, kritisch für wichtige Geräte nach 60 Minuten. Ändern mit `--discovery-interval`, `--portscan-interval`, `--scan-preset`, `--scan-ports`, `--discovery-ports`, `--offline-info`, `--offline-warn`, `--offline-critical`. Oder in der Weboberfläche unter „Netze & Crawler“. Der Portscan geht bis hinunter auf 15 Minuten (`--portscan-interval 30m`).

Ein bestehendes Netz ändern – Inventar und Verlauf bleiben erhalten, am Crawler ist nichts zu tun (jeder Job bringt Ziele und Ports mit, die Änderung gilt ab dem nächsten geplanten Scan):

- Weboberfläche: „Netze & Crawler“ → „Bearbeiten“ in der Zeile des Netzes.
- Kommandozeile: ändert nur die angegebenen Einstellungen, z. B.

```bash
docker compose run --rm server network update --id 1 --portscan-interval 30m
```

Findet die Erkennung nach dem Initialbestand einen neuen Host, legt der Server sofort einen Portscan nur für diesen Host an. Der tägliche Portscan verschiebt sich dadurch nicht.

### 5. Ergebnisse ansehen

```bash
docker compose run --rm server hosts
docker compose run --rm server events
docker compose run --rm server network list
docker compose run --rm server network scan --id 1 --kind discovery   # sofort erkennen
```

### Crawler manuell einrichten (ohne Installer)

Für andere Systeme oder die Docker-Variante: Mit `crawler add` erhält man das Secret (einmalig angezeigt). Dann `agent.secret` (Rechte `600`) und `agent.json` nach `configs/agent.example.json` anlegen, mit **derselben Freigabe** unter `limits` und bei selbstsigniertem Zertifikat `"tls_pin": "sha256//…"` (steht im Server-Log). Start: `netcrawl-agent --config agent.json` (`--once` für einen einzelnen Abruf).

Vor jedem Netzwerkzugriff prüft der Crawler: gültige Konfiguration inkl. `crawler_id`, `polling.interval_seconds >= 60`, gültige Freigabe (private Bereiche, Hostlimit), kein bereits laufender Crawl (Lock-Datei). Schlägt etwas fehl, beendet er sich ohne Request. Exit-Codes bei `--once`: `0` ok, `1` Fehler, `2` Job lokal abgelehnt. Im Dauerbetrieb: `3`, wenn der Server den Crawler dreimal in Folge ablehnt.

## Admin-API

| Methode | Pfad | Zweck |
|---|---|---|
| `POST` | `/api/v1/admin/login`, `/logout` | An-/Abmelden (Session-Cookie) |
| `GET` | `/api/v1/admin/me` | aktueller Benutzer |
| `GET`/`POST` | `/api/v1/admin/crawlers` | Crawler auflisten / registrieren (Secret einmalig in der Antwort) |
| `PUT` | `/api/v1/admin/crawlers/{id}` | `{"enabled": false}` sperrt, `true` entsperrt; `{"allow": [...], "max_hosts": N}` ändert die Freigabe (danach Neuinstallation) |
| `GET`/`PUT` | `/api/v1/admin/settings/public-url` | Server-Adresse für Installationsbefehle (wenn nicht per `NETCRAWL_PUBLIC_URL` gesetzt) |
| `POST` | `/api/v1/admin/crawlers/{id}/enroll` | `{"reverse_dns": true}` → Installationsbefehl mit Einmal-Code |
| `GET`/`POST` | `/api/v1/admin/networks` | Netze auflisten / anlegen |
| `PUT` | `/api/v1/admin/networks/{id}` | Netz ändern – ersetzt **alle** Einstellungen (nicht angegebene fallen auf den Standard zurück), daher das ganze Netz schicken. Portscan-Intervall: `portscan_interval_minutes` (min. 15; `portscan_interval_hours` geht weiterhin) |
| `POST` | `/api/v1/admin/networks/{id}/scan` | `{"kind": "discovery"}` oder `{"kind": "ports"}` sofort |
| `GET` | `/api/v1/admin/hosts?network_id=` | Inventar |
| `POST` | `/api/v1/admin/hosts/important` | `{"network_id", "ip", "important"}` |
| `GET` | `/api/v1/admin/port-presets` | eingebaute Port-Auswahlen mit ihren Ports |
| `POST` | `/api/v1/admin/hosts/name` | `{"network_id", "ip", "name"}` – eigener Name (max. 64 Zeichen, `""` entfernt ihn) |
| `GET` | `/api/v1/admin/events?network_id=&ip=&baseline=1&limit=` | Ereignisse, neueste zuerst |
| `GET`/`PUT` | `/api/v1/admin/notifications` | Discord-Einstellungen (`discord_url`, `min_severity`, `enabled`, `clear_discord_url`); die URL wird nie zurückgegeben |
| `POST` | `/api/v1/admin/notifications/test` | Testnachricht senden |
| `GET`/`POST` | `/api/v1/admin/jobs` | Jobs auflisten / einzelnen Job anlegen |
| `GET` | `/api/v1/admin/jobs/{id}` | Job mit Ergebnis |
| `GET` | `/api/v1/admin/audit` | Audit-Log |

Schreibende Requests mit Session-Cookie müssen `Content-Type: application/json` senden (Schutz gegen Cross-Site-Requests, zusätzlich zu `SameSite=Strict`).

## Sicherheitshinweise

- Einmal-Codes werden nur als SHA-256 gespeichert, gelten einmal und 30 Minuten. Wer einen gültigen Code abfängt und zuerst einlöst, kann sich als dieser Crawler ausgeben: Er sieht dessen Jobs (Ziele, Ports) und kann falsche Ergebnisse melden. Deshalb den Befehl nicht weitergeben und zeitnah ausführen. Ein fremdes Einlösen fällt auf: Es steht im Audit-Log (`crawler.enroll` mit IP), und die eigene Installation scheitert mit „code already used“. Dann den Crawler deaktivieren und neu anlegen.
- Crawler-Secrets und Result-Tokens liegen im Klartext in der Datenbank, weil der Server sie zur HMAC-Prüfung braucht. Datenbank-Zugriff und Backups entsprechend schützen.
- Admin-Passwörter werden mit bcrypt gespeichert, Session-Tokens nur als SHA-256.
- Anmeldungen, Registrierungen, Netz- und Job-Anlagen, Auslieferungen, angenommene/abgelehnte Ergebnisse und Fehler des Schedulers stehen im Audit-Log.
- Vor dem ersten echten Scan: Umfang, Deny-Liste, Zeitfenster und Abbruchweg festlegen (siehe Projektnotiz „Start – Netzwerk-Inventarisierung & Scan-Vorbereitung“).

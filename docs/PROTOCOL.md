# Crawler-Protokoll (v1)

Verbindliche Spezifikation der Kommunikation zwischen `netcrawl-agent` (Crawler) und `netcrawl-server`. Implementiert in `internal/protocol`.

## Grundsätze

- Der **Crawler fragt**, der Server antwortet. Der Crawler braucht keinen offenen Port.
- Jeder Request des Crawlers ist mit **HMAC-SHA256** signiert.
- Job-Abfragen werden mit dem **Crawler-Secret** signiert (32 Byte, bei der Registrierung einmalig ausgegeben).
- Ergebnisse werden mit dem **Result-Token** des Jobs signiert. Es wird mit dem Job ausgeliefert, ist an `job_id` und `crawler_id` gebunden, gilt für genau ein angenommenes Ergebnis und wird **nie zurückgesendet**.
- Der Crawler prüft jeden Job **lokal**, bevor er eine Verbindung aufbaut (siehe „Jobvalidierung“). Der Server kann ihn nicht über seine lokalen Grenzen hinaus anweisen.
- Schlüssel werden als base64url ohne Padding übertragen.

## Signaturzeichenfolge

```text
NETCRAWL-HMAC-SHA256-V1
<HTTP-Methode>
<Request-Pfad>
<crawler_id>
<job_id oder leer bei Job-Abfragen>
<Unix-Zeitstempel in Sekunden>
<Nonce>
<SHA-256 des unveränderten Request-Bodys, hex, Kleinbuchstaben>
```

Die Zeilen werden mit `\n` verbunden, ohne abschließenden Zeilenumbruch. Die Signatur ist `hex(HMAC-SHA256(Schlüssel, Signaturzeichenfolge))` in Kleinbuchstaben. Der Server vergleicht in konstanter Zeit.

- **Zeitstempel:** höchstens ±5 Minuten Abweichung von der Serverzeit, sonst `401`.
- **Nonce:** 16–128 Zeichen `[0-9A-Za-z_-]`, pro Crawler nur einmal verwendbar (Job-Abfragen und Ergebnisse teilen sich den Nonce-Raum). Wiederverwendung → `409`.

## Job abholen

```http
GET /api/v1/crawler/job
X-Crawler-Id: pilot-1
X-Request-Nonce: 3f9a…
X-Request-Timestamp: 1767225600
X-Request-HMAC: 9c1e…            (Schlüssel: Crawler-Secret, job_id leer)
```

| Status | Bedeutung |
|---|---|
| `200` | Job im Body (siehe unten); der Job ist danach `delivered` und wird nicht erneut ausgeliefert |
| `204` | kein Job |
| `401` | unbekannter/deaktivierter Crawler, ungültige Signatur, Zeitstempel außerhalb des Fensters |
| `409` | Nonce bereits verwendet |

Der Crawler sendet `User-Agent: netcrawl-agent/<Version>`; der Server merkt sich die Version (Anzeige „veraltet“). Bei `200` und `204` antwortet der Server mit `X-NetCrawl-Version: <Server-Version>`. Weicht sie ab, bittet der Crawler seinen lokalen Updater um ein Update (siehe SERVER.md, „Crawler aktualisieren sich selbst“). Beides ist nicht signiert und dient nur als Hinweis: Der Updater lädt und prüft das neue Programm selbst über den gepinnten TLS-Schlüssel.

```json
{
  "job_id": "3757488f-b622-4ee7-bb9a-4618e6065c03",
  "crawler_id": "pilot-1",
  "created_at": "2026-09-04T12:00:00Z",
  "expires_at": "2026-09-04T12:05:00Z",
  "targets": ["127.0.0.1/32"],
  "max_hosts": 1,
  "ports": [22, 80],
  "timeout_ms": 500,
  "kind": "discovery",
  "deny": ["127.0.0.4"],
  "reverse_dns": true,
  "result_token": "<43 Zeichen base64url>"
}
```

Felder für Netz-Jobs des Schedulers:

- `kind`: `discovery` (wer ist online?) oder `ports` (welche Ports sind offen?). Fehlt das Feld, gilt `ports`.
- `deny`: Adressen/Bereiche innerhalb der Ziele, die nicht kontaktiert werden.
- `reverse_dns`: Hostnamen per PTR abfragen – nur wenn auch die lokale Crawler-Konfiguration `reverse_dns: true` hat.
- `services` (Portscan-Jobs, wenn die Diensterkennung des Netzes fällig ist): Dienst und Version hinter den gefundenen offenen Ports erkennen (`nmap -sV`, falls installiert, sonst Banner/HTTP/TLS) und in `details` melden (`service`, `product`, `serviceVersion`, `serviceExtra`, `serviceMethod`). Es werden nur Ports kontaktiert, die der Scan offen gefunden hat; mit `no_service_detection: true` in der lokalen Konfiguration nie.

In beiden Arten meldet der Crawler auch Hosts ohne offenen Port, die eine Verbindung aktiv abgelehnt haben (sie sind online).

## Jobvalidierung im Crawler (nach GET, vor jedem TCP-Connect)

Ein Job wird nur ausgeführt, wenn:

1. `job_id` eine UUID ist (sie wird in den Ergebnis-Pfad eingesetzt) und `crawler_id` zur lokalen Konfiguration passt,
2. `expires_at` noch in der Zukunft liegt,
3. jedes Ziel vollständig in **einem** Eintrag der lokalen `limits.allow` liegt,
4. `max_hosts` ≤ lokales `limits.max_hosts` und die Zahl der tatsächlich adressierten Hosts ≤ `max_hosts`,
5. die Portliste gültig ist (1–65535, keine Duplikate, höchstens 1024 Ports),
6. `timeout_ms` zwischen 1 und 10.000 liegt, `kind` bekannt ist, die `deny`-Einträge gültig sind und das Result-Token dekodierbar ist.

Bei jeder Ablehnung: **kein TCP-Connect und kein Ergebnis-POST.** Der Crawler protokolliert den Grund lokal.

Jobs werden ausschließlich als TCP-Connect-Scan ausgeführt, ohne Dienst-Erkennung (die würde zusätzliche Verbindungen öffnen). Reverse-DNS nur, wenn Job und lokale Konfiguration es erlauben.

## Ergebnis abgeben

```http
POST /api/v1/crawler/jobs/{job_id}/result
Content-Type: application/json
X-Crawler-Id: pilot-1
X-Result-Nonce: 7b2c…
X-Result-Timestamp: 1767225610
X-Result-HMAC: 51aa…              (Schlüssel: Result-Token, job_id gesetzt)

{"job_id":"…","crawler_id":"pilot-1","agent_version":"…","started":"…","finished":"…","networks":[ … ]}
```

`networks` enthält pro `/24` dasselbe Format wie die JSON-Dateien des CLI (`results/*.json`).

Der Server prüft in dieser Reihenfolge:

| Prüfung | Fehler |
|---|---|
| Header vollständig, Zeitstempel im Fenster | `401` |
| Job existiert | `401` |
| Job gehört zu `X-Crawler-Id` | `403` |
| Signatur mit dem Result-Token gültig (Body unverändert) | `401` |
| Body ist ein gültiges Ergebnis mit passender `job_id`/`crawler_id` | `400` |
| *atomar in einer Datenbank-Transaktion, Zeile des Jobs gesperrt:* | |
| – Job gehört zum Crawler und wurde ausgeliefert, Signatur gültig (erneut) | `403` / `401` |
| – noch kein Ergebnis angenommen, Nonce unbenutzt | `409` (`"replay"`) |
| – Job nicht abgelaufen | `410` |

Erfolg: `201`. Die Signatur wird geprüft, bevor der Body ausgewertet wird. Ein manipulierter Body ergibt deshalb `401` und keinen Formatfehler. Abgelehnte Abgaben verbrauchen weder Nonce noch Job. Jede Annahme und Ablehnung landet im Audit-Log.

## Server-seitige Grenzen beim Anlegen von Jobs

Ein Job wird nur angelegt, wenn seine Ziele in der **serverseitigen** Allowlist des Crawlers liegen und `max_hosts` dessen Limit nicht überschreitet. TTL 1–60 Minuten (Standard 5), Timeout 1–10.000 ms (Standard 500).

## Freigabe

Was ein Crawler scannen darf, steht an zwei Stellen (`internal/scope`, `CheckRelease`):

- **Server:** Allowlist und Hostlimit bei der Registrierung. Jobs außerhalb werden nicht angelegt.
- **Crawler:** `limits.allow` und `limits.max_hosts` in `agent.json`. Jobs außerhalb werden vor jedem Connect abgelehnt.

Beide Seiten akzeptieren nur private Bereiche (RFC 1918, Loopback, Link-Local, CGNAT). Der Crawler erlaubt öffentliche Bereiche nur mit `"allow_public_ranges": true`; der Server gar nicht. Hostlimit 1–65.536.

## Installation (Einmal-Code)

Der Admin erzeugt für einen registrierten Crawler einen Einmal-Code (`POST /api/v1/admin/crawlers/{id}/enroll`). Der Code ist ein 32-Byte-Schlüssel in base64url, gilt **30 Minuten** und **einmal**; gespeichert wird nur sein SHA-256. Ein neuer Code für denselben Crawler macht unbenutzte ältere ungültig.

| Methode | Pfad | Zweck |
|---|---|---|
| `GET` | `/install/{code}` | Installationsskript (`text/x-shellscript`) mit Server-URL, Pin, Code und SHA-256 der Crawler-Programme. Verbraucht den Code nicht. `404` bei unbekanntem, benutztem oder abgelaufenem Code. |
| `GET` | `/install/agent/linux-{amd64,arm64}` | Crawler-Programm |
| `GET` | `/install/uninstall` | Deinstallationsskript |
| `POST` | `/install/enroll` | Code einlösen (unten) |

```http
POST /install/enroll
Content-Type: application/json

{"token": "<Code>", "agent_version": "…"}
```

Antwort `200`:

```json
{
  "crawler_id": "lan-1",
  "secret": "<neues Crawler-Secret, base64url>",
  "allow": ["192.168.1.0/24"],
  "max_hosts": 256,
  "reverse_dns": true,
  "interval_seconds": 60
}
```

Das Einlösen läuft atomar: Code als benutzt markieren und Crawler-Secret **ersetzen**. Ein bereits installierter Crawler mit dem alten Secret wird damit abgemeldet. Fehler: `404` (Code unbekannt, benutzt oder abgelaufen), `403` (Crawler deaktiviert).

`netcrawl-agent enroll` prüft die Antwort, bevor es etwas schreibt: gültige `crawler_id`, gültiges Secret, Freigabe nur aus privaten Bereichen (`allow_public_ranges` lässt sich über die Installation nicht setzen). Danach schreibt es `agent.json` (die Freigabe steht dann fest) und `agent.secret` (`600`).

## Transport

Plain HTTP akzeptiert der Crawler nur zu einem Server auf Loopback. Für jeden anderen Server ist HTTPS Pflicht, weil Job-Antworten Result-Tokens enthalten. Der Crawler folgt keinen Redirects.

Bei einem selbstsignierten Server-Zertifikat steht in `agent.json` `"tls_pin": "sha256//<base64>"`: Der Crawler akzeptiert dann nur ein Zertifikat mit genau diesem öffentlichen Schlüssel (SHA-256 der SubjectPublicKeyInfo, dasselbe Format wie `curl --pinnedpubkey`). Name und CA werden nicht geprüft, der Pin ist der Vertrauensanker. `tls_pin` und `ca_file` schließen sich aus.

Ein deaktivierter Crawler erhält auf Job-Abfragen `401`, seine Ergebnisse werden mit `401` abgelehnt. Nach `3` abgelehnten Abfragen in Folge beendet sich der Crawler mit Exit-Code `3` (Secret ersetzt, Crawler gesperrt oder Uhr mehr als 5 Minuten falsch); die systemd-Unit startet ihn dann nicht neu (`RestartPreventExitStatus=3`).

Ändert der Admin die Freigabe eines Crawlers, verfallen dessen offene Jobs, und der Crawler wird als „Neuinstallation nötig“ markiert, bis ein Einmal-Code eingelöst wird. Die lokale Freigabe ändert sich nur durch die Neuinstallation.

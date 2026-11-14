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
  "result_token": "<43 Zeichen base64url>"
}
```

## Jobvalidierung im Crawler (nach GET, vor jedem TCP-Connect)

Ein Job wird nur ausgeführt, wenn:

1. `job_id` eine UUID ist (sie wird in den Ergebnis-Pfad eingesetzt) und `crawler_id` zur lokalen Konfiguration passt,
2. `expires_at` noch in der Zukunft liegt,
3. jedes Ziel vollständig in **einem** Eintrag der lokalen `limits.allow` liegt,
4. `max_hosts` ≤ lokales `limits.max_hosts` und die Zahl der tatsächlich adressierten Hosts ≤ `max_hosts`,
5. die Portliste gültig ist (1–65535, keine Duplikate, höchstens 1024 Ports),
6. `timeout_ms` zwischen 1 und 10.000 liegt und das Result-Token dekodierbar ist.

Bei jeder Ablehnung: **kein TCP-Connect und kein Ergebnis-POST.** Der Crawler protokolliert den Grund lokal.

Jobs werden ausschließlich als TCP-Connect-Scan ausgeführt: kein Reverse-DNS (würde den Resolver kontaktieren) und keine Dienst-Erkennung (würde zusätzliche Verbindungen öffnen).

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

## Pilot-Beschränkung

In dieser Version ist ausschließlich der **Loopback-Pilot** freigegeben (`internal/scope`, `PilotOnly`):

- Crawler-Allowlist genau `["127.0.0.1/32"]`, `max_hosts` genau `1` – sowohl in der Agent-Konfiguration als auch bei der Registrierung auf dem Server.

Erweiterung auf echte Netze erst nach schriftlich festgelegtem Umfang und Freigabe, als eigene Code-Änderung.

## Transport

Plain HTTP akzeptiert der Crawler nur zu einem Server auf Loopback. Für jeden anderen Server ist HTTPS Pflicht, weil Job-Antworten Result-Tokens enthalten. Der Crawler folgt keinen Redirects.

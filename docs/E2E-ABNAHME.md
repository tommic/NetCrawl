# E2E-Abnahme: Loopback-Pilot

Umsetzung der Abnahme „Crawler-/Mock-Prototyp (Loopback-only)“. Die Testfälle E2E-01 bis E2E-07 sind als automatisierte Tests in [`internal/e2e`](../internal/e2e/e2e_test.go) umgesetzt und erzeugen auf Wunsch den geforderten Abnahmebeleg.

## Ausführen

```bash
make e2e                                   # In-Memory-Datenhaltung
NETCRAWL_TEST_DATABASE_URL='postgres://…/netcrawl_test?sslmode=disable' make e2e   # mit PostgreSQL (Datenbank wird geleert!)
make e2e VERSION=v0.2.0                    # Versionskennung im Beleg
```

Der Beleg landet in `e2e-report.md`. Die CI erzeugt ihn bei jedem Push gegen PostgreSQL und stellt ihn als Artefakt `e2e-report` bereit.

## Aufbau

- Server und Crawler laufen im Testprozess und sprechen echtes HTTP über `127.0.0.1`.
- **Jeder HTTP-Request** des Crawlers und **jeder TCP-Verbindungsversuch** des Scanners wird aufgezeichnet. Daraus entstehen die Nachweise „kein Connect“ und „kein POST“.
- Einziges erlaubtes Scan-Ziel ist ein Listener auf `127.0.0.1`, den der Test selbst startet. Als zusätzliches Sicherheitsnetz verweigert der Test-Dialer jede Verbindung zu einer anderen Adresse, ohne sie aufzubauen.
- Für E2E-05 und E2E-06 wird ein unzulässiger Job **direkt in die Datenbank** geschrieben (simulierter kompromittierter Server), weil der Server ihn über die Admin-API korrekt ablehnt (`400`). So ist nachgewiesen, dass beide Seiten unabhängig voneinander schützen.

## Testfälle

| ID | Fall | Umsetzung | Erwartung |
|---|---|---|---|
| E2E-01 | Gültiger Job, TTL 5 min, `127.0.0.1/32`, `max_hosts: 1` | Job über die Service-Schicht angelegt, Crawler `RunOnce` | Connects nur zu `127.0.0.1`, Ergebnis `201`, Job `completed` |
| E2E-02 | Body nach HMAC-Bildung verändert | Transport ändert den Body nach dem Signieren | `401`/`403`, kein Ergebnis gespeichert |
| E2E-03 | Identisches Ergebnis erneut abgeben | Der aufgezeichnete POST wird bitgleich wiederholt | `409 Replay`, genau ein Ergebnis angenommen |
| E2E-04 | Abgelaufener Job | Teil 1: TTL 1 min, Crawler-Uhr 2 min später → lokale Ablehnung. Teil 2: korrekt signiertes Ergebnis nach Ablauf | Teil 1: kein Connect, kein POST. Teil 2: `410` |
| E2E-05 | `127.0.0.2/32`, privates Netz, nicht erlaubtes Ziel | `127.0.0.2/32`, `192.168.1.10/32`, `10.0.0.0/8`, `127.0.0.0/8` | Admin-API `400`; injizierter Job lokal abgelehnt, kein Connect, kein POST |
| E2E-06 | Scope über `max_hosts: 1` | `max_hosts: 2`, `127.0.0.0/30` mit `max_hosts: 4`, zwei Ziele | wie E2E-05 |
| E2E-07 | `polling.interval_seconds < 60` | Werte 59, 0, −1 (60 als Gegenprobe) | Config-Load schlägt fehl, kein Polling/Connect/POST |
| V-01 | Vorabvalidierung „kein laufender Crawl“ | zweiter Start mit derselben Lock-Datei | Abbruch vor jedem Netzwerkzugriff |

## Abnahmebeleg

Pro Testfall enthält `e2e-report.md`:

- Testzeit und Build-/Versionskennung,
- anonymisierte Requests (`[Quelle] Methode Pfad → Status`, Job-IDs als `<job>`),
- tatsächliche Zieladressen aller TCP-Connects,
- Ergebnis und bei Fehlfällen den Nachweis, dass kein Connect und kein POST erfolgte.

Requests, die der Test selbst sendet (z. B. die Wiederholung in E2E-03 oder Teil 2 von E2E-04), sind als `[Test, manuell]` gekennzeichnet.

> Dieser automatisierte Beleg ersetzt nicht die Dokumentation der Abnahme selbst. Nach dem Lauf das Dokument „E2E-Abnahme“ mit dem erzeugten Beleg als bestanden markieren.

# NetCrawl – Architektur

## Ziel

NetCrawl inventarisiert Hosts in eigenen bzw. autorisierten IPv4-Netzen. Der Scanner verarbeitet einzelne IPs, Bereiche und CIDR-Netze, berücksichtigt eine Denylist, prüft konfigurierte TCP-Ports und versucht für gefundene Hosts Reverse-DNS.

Die Scan-Rohdaten werden pro `/24` als JSON gespeichert. CSV- und Markdown-Dateien sind abgeleitete Exporte und können jederzeit neu erzeugt werden.

## Datenfluss

```text
.env
 │
 ├── CONFIG
 ├── RESULTS
 └── EXPORT
 │
 ▼
config.json
 │
 ▼
netcrawler
 │
 ├── Target Parser
 ├── Denylist
 ├── /24 Gruppierung
 ├── TCP Connect Scanner
 └── Reverse DNS
 │
 ▼
results/*.json
 │
 ├──────────────┐
 ▼              ▼
result2csv      result2md
 │              │
 ▼              ▼
export/*.csv    export/*.md
```

`results/*.json` ist das interne Austauschformat. Exporte verändern die Rohdaten nicht.

## Lokale Konfiguration

`.env.example` ist die versionierte Vorlage:

```bash
CONFIG=config.json
RESULTS=results
EXPORT=export
```

Die lokale `.env` wird vom Script `netcrawl` geladen und nicht committed.

`CONFIG` bestimmt die Scan-Konfiguration, `RESULTS` das JSON-Ergebnisverzeichnis und `EXPORT` das Ziel für CSV/Markdown.

`config.json` ist ebenfalls lokal. Die versionierte Vorlage befindet sich unter `configs/example.json`.

## Targets

Unterstützt werden:

```text
192.168.1.20
192.168.1.0/24
192.168.1.20-192.168.1.80
```

IPv6 ist im MVP nicht vorgesehen.

## Denylist

Die Denylist akzeptiert dieselben IPv4-Formate wie die Include-Targets. Ein Deny-Eintrag hat Vorrang vor Include.

Ist ein komplettes `/24` vollständig durch die Denylist blockiert, entsteht dafür kein Network-Job und keine Ergebnisdatei. In diesem Fall wird stattdessen eine INFO-Meldung ausgegeben (`Network X fully denied (N address(es)), skipping`), damit der Block sichtbar bleibt statt kommentarlos zu verschwinden.

## Arbeitseinheit `/24`

Targets werden für die Verarbeitung und Ergebnisablage nach `/24` gruppiert.

Beispiel:

```text
192.168.10.0/24 → results/192.168.10.0_24.json
```

Mehrere Targets innerhalb desselben `/24` landen im selben Network-Job.

Die Planung (`internal/engine/plan.go`) speichert pro Job nur das `/24` und die Anzahl der Ziele bzw. ausgeschlossenen Adressen. Die einzelnen Adressen werden erst beim Scannen des jeweiligen Netzes erzeugt; überlappende Include-Targets werden dabei nur einmal gezählt. So bleibt auch ein großes Target klein im Speicher.

Ein einzelner Lauf ist auf höchstens 65.536 `/24`-Netze (die Größe eines `/8`) begrenzt. Ein vertipptes Präfix wie `10.0.0.0/1` bricht dadurch sofort mit einer Fehlermeldung ab, statt Millionen Jobs zu planen.

## Scan-Engine

Die Ablauflogik liegt im Paket `internal/engine` und nicht mehr in `cmd/netcrawler`. Das CLI ist nur noch eine dünne Hülle: Es lädt die Konfiguration, erstellt den Plan, startet die Engine und schreibt jedes fertige Netz über `result.Write` als JSON. Ein späterer Server kann dieselbe Engine nutzen und die Ergebnisse stattdessen in der Datenbank speichern.

```text
config.Load  →  engine.BuildPlan  →  engine.Run(ctx, plan, sink)
                                         │
                                         ├── tcp.Scan
                                         ├── probe.Enrich   (optional)
                                         ├── Reverse DNS    (parallel, optional)
                                         └── sink(result)   → results/*.json
```

## Server und Crawler

Neben dem CLI gibt es einen zentralen Server (`netcrawl-server`, PostgreSQL) und Crawler (`netcrawl-agent`). Der Crawler holt zeitlich begrenzte Jobs per signiertem Request ab, prüft sie gegen seine **lokale** Allowlist und sein Hostlimit, scannt mit derselben Engine wie das CLI und meldet das Ergebnis mit HMAC signiert zurück. Details: [`SERVER.md`](SERVER.md), [`PROTOCOL.md`](PROTOCOL.md), Abnahme: [`E2E-ABNAHME.md`](E2E-ABNAHME.md).

```text
netcrawl-server ──(Job: Ziele, Ports, Ablauf, Result-Token)──► netcrawl-agent
       ▲                                                          │ lokale Prüfung
       │                                                          ▼
   PostgreSQL ◄──(Ergebnis, HMAC mit Result-Token, einmalig)── engine.Run
```

Netze, Inventar und Ereignisse (M2): Ein Scheduler im Server erzeugt pro Netz regelmäßig Host-Erkennungs- und Portscan-Jobs. Ergebnisse aktualisieren das Inventar (`internal/inventory`) in einer Datenbank-Transaktion; daraus entstehen Ereignisse für neue, verschwundene und wiederkehrende Hosts, Hostname-Wechsel sowie geöffnete und geschlossene Ports. Details in [`SERVER.md`](SERVER.md).

## Abbruch (Strg+C)

- **Erstes** Strg+C bzw. `SIGTERM`: Das gerade laufende `/24` wird noch fertig gescannt und geschrieben, danach endet der Lauf. Weitere Netze werden nicht mehr begonnen.
- **Zweites** Strg+C: sofortiger Abbruch. Das unvollständige `/24` wird **nicht** geschrieben, damit keine halben Ergebnisse als vollständig erscheinen.

Exit-Codes: `0` = vollständig, `1` = Fehler (z. B. ungültige Konfiguration), `130` = abgebrochen.

## Konfigurationsprüfung

`config.json` wird vor jedem Netzwerkzugriff vollständig geprüft. Alle gefundenen Fehler werden gemeinsam gemeldet:

- unbekannte Schlüssel (Tippfehler wie `"timout"`) – Groß-/Kleinschreibung wird dabei wie bei Go üblich ignoriert,
- `version` ungleich `1`, leere oder ungültige `targets.include`, ungültige `targets.deny`,
- unbekanntes `ports.preset`, ungültige Ports oder Bereiche in `ports.custom`, keine Ports trotz `ports.enabled: true`,
- Timeouts außerhalb von 1–60.000 ms, `performance.maxConcurrentConnections` außerhalb von 1–10.000.

Fehlende Werte (`0` bzw. nicht gesetzt) erhalten weiterhin die Standardwerte.

## TCP Scanner

Der MVP verwendet einen parallelen TCP-Connect-Scan. Dadurch sind keine Raw Sockets und normalerweise keine Root-Rechte erforderlich.

Konfigurierbar sind insbesondere Port-Preset, zusätzliche Ports, Timeout und maximale Parallelität.

Presets (`ports.preset`):

| Preset | Ports |
|---|---|
| `tiny` | 22, 80, 443 |
| `common` | 21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443 |
| `web` | 80, 443, 8000, 8080, 8081, 8443, 8888 |
| `database` | 1433, 1521, 3306, 5432, 6379, 27017 |
| `all` | 1–65535 |
| `custom` (oder leer) | nur die Einträge aus `ports.custom` |

`ports.custom` ergänzt das Preset um einzelne Ports oder Bereiche, als Zahl oder als Text:

```json
"custom": [8000, "8080", "9000-9010"]
```

Ein unbekanntes Preset oder ein ungültiger Eintrag ist ein Fehler und wird nicht stillschweigend ignoriert. Implementiert in `internal/ports`.

Über `ports.enabled` lässt sich der TCP-Scan vollständig deaktivieren (z. B. um Target-Auflösung und Denylist zu testen, ohne das Netz tatsächlich zu berühren). Ist der Wert `false`, werden keine Verbindungen aufgebaut; alle Hosts gelten als nicht responsive.

## Reverse DNS

Für Hosts mit gefundenen offenen Ports kann ein PTR-/Reverse-DNS-Lookup durchgeführt werden. Ein fehlender PTR-Eintrag ist kein Scanfehler.

Die Lookups laufen parallel, höchstens 32 gleichzeitig, damit der lokale Resolver nicht überlastet wird.

## Service-Erkennung (Enrichment)

Über `enrichment.enabled` kann `netcrawler` für bestimmte offene Ports zusätzlich versuchen, das dahinterliegende Programm grob zu identifizieren, ohne eine vollständige Protokoll-/Versionserkennung durchzuführen:

- **TLS-Zertifikat** bei Port `443`/`8443`: Subject-CN, Issuer-CN und Ablaufdatum. `InsecureSkipVerify` ist hier bewusst gesetzt – es wird nur ausgelesen, welches Zertifikat der Host präsentiert, nichts wird auf Basis der Gültigkeit vertraut oder übertragen. Zusätzlich wird über dieselbe TLS-Verbindung ein `GET /` abgesetzt, um wie beim reinen HTTP-Check Titel/Server-Header zu bekommen – bei vielen Geräten (z. B. Admin-Oberflächen) ist das die aussagekräftigste Information überhaupt.
- **HTTP-Titel/Server-Header** bei Port `80`/`8000`/`8080`/`8081`/`8888`: einfacher `GET /`, ausgewertet werden `<title>` und der `Server`-Header.
- **Banner** bei Port `21`/`22`/`25`/`110`/`143`: die ersten Bytes, die der Dienst direkt nach dem Verbindungsaufbau selbst schickt (z. B. der SSH-Versionsstring).
- **SSH-Host-Key** zusätzlich bei Port `22`: Typ und SHA256-Fingerprint des Host-Keys, wie ihn `ssh-keyscan` liefert. Dazu wird der SSH-Handshake nur bis zur Host-Key-Verifikation durchgeführt und danach bewusst mit einem Fehler abgebrochen – es wird nie ein Benutzername, Passwort oder Schlüssel gesendet, es findet also nie ein Login-Versuch statt. Umgesetzt mit `golang.org/x/crypto/ssh` (erste externe Abhängigkeit des Projekts).

Jeder Check läuft unabhängig, mit eigenem Timeout (`enrichment.timeoutMs`) und eigener Verbindung zusätzlich zum Port-Scan selbst. Ein nicht antwortender oder nicht erkannter Dienst führt zu keinem Fehler – der Port bleibt dann einfach ohne `details`-Eintrag.

Implementiert in `internal/scanner/probe`.

**Hinweis zum Bauen:** Die SSH-Host-Key-Erkennung braucht die Standardbibliothekspakete `crypto/ecdh` (seit Go 1.20). Falls `go version` einen gccgo-Compiler statt des offiziellen Go-Toolchains zeigt (wie es diese Umgebung standardmäßig tut, `go` zeigt auf gccgo 1.18), damit lässt sich das Projekt nicht mehr bauen – stattdessen z. B. `/usr/lib/go-1.22/bin/go` verwenden bzw. die PATH-Reihenfolge anpassen.

## JSON-Ergebnis

Beispiel:

```json
{
  "schemaVersion": 1,
  "scanId": "20260905-101500",
  "configHash": "sha256:3f1c…",
  "network": "192.168.1.0/24",
  "scanStarted": "2026-09-05T10:15:00Z",
  "scanFinished": "2026-09-05T10:15:08Z",
  "hosts": {
    "192.168.1.20": {
      "hostname": "server.local",
      "ports": [22, 80, 443],
      "details": {
        "22": {
          "banner": "SSH-2.0-OpenSSH_9.6",
          "sshKeyType": "ecdsa-sha2-nistp256",
          "sshKeyFingerprint": "SHA256:<Fingerprint des Host-Keys>"
        },
        "443": {
          "tlsSubject": "router.local",
          "tlsIssuer": "MyRouter CA",
          "tlsNotAfter": "2027-01-01"
        }
      }
    }
  },
  "statistics": {
    "scanned": 253,
    "denied": 1,
    "responsive": 1,
    "openPorts": 3
  }
}
```

`details` ist optional und pro Port nur vorhanden, wenn `enrichment.enabled` gesetzt ist und der jeweilige Port zu den oben genannten Kategorien gehört und geantwortet hat.

Nur Hosts mit gefundenen offenen Ports erscheinen im aktuellen MVP als responsive Hosts.

Scan-Metadaten:

- `scanId` – Startzeit des Laufs (UTC, `JJJJMMTT-hhmmss`); alle Netze eines Laufs tragen dieselbe ID.
- `configHash` – SHA-256 über die ergebnisrelevanten Einstellungen: Targets, aufgelöste Portliste, Port-Timeout, Hostname- und Enrichment-Einstellungen. Ausgabeverzeichnis, `prettyPrint` und Parallelität fließen nicht ein, weil sie das Ergebnis nicht verändern.
- `scanStarted` / `scanFinished` – Beginn und Ende dieses `/24` (RFC 3339, UTC).

Damit lässt sich später erkennen, ob ein Netz bereits vollständig mit derselben Konfiguration gescannt wurde (Grundlage für Resume und Scan-Vergleich). Ältere Ergebnisdateien ohne diese Felder bleiben gültig; alle Leser behandeln sie als optional.

## CSV Export

`result2csv` liest eine JSON-Datei oder ein Ergebnisverzeichnis.

```bash
./result2csv --input ./results --output ./export
```

Aus einem Ergebnisverzeichnis entstehen `all.csv` sowie einzelne Dateien pro `/24`.

Ein Host entspricht genau einer CSV-Zeile. Ports werden gemeinsam im Feld `ports` gespeichert. Vorhandene Service-Erkennungsdaten (siehe oben) landen im Feld `details`, pro Port ein durch `; ` getrennter Eintrag, z. B. `443: cn=router.local issuer=MyRouter CA expires=2027-01-01`.

Zeilen werden zunächst nach Netzwerk und dann nach IP-Adresse sortiert – numerisch, nicht als Text. `192.168.0.3` steht damit vor `192.168.0.102`, und `192.168.2.0/24` vor `192.168.10.0/24`.

## Markdown Export

`result2md` arbeitet analog:

```bash
./result2md --input ./results --output ./export
```

Es entstehen `all.md` und einzelne Reports pro `/24`.

Wie beim CSV-Export werden Netzwerke und IP-Adressen numerisch sortiert, nicht als Text. Die Tabelle bekommt eine vierte Spalte `Details` mit denselben Service-Erkennungsdaten, ein Eintrag pro Port und Zeile (per `<br>` getrennt).

## Workflow Script

`netcrawl` verbindet die einzelnen Programme und lädt vorher `.env`.

```text
./netcrawl scan
./netcrawl csv
./netcrawl md
./netcrawl export
./netcrawl all
```

`export` erzeugt CSV und Markdown ohne neuen Scan. `all` führt Scan, CSV und Markdown nacheinander aus.

`./netcrawl -h` bzw. `--help` zeigt eine Kurzübersicht der Commands. Fehlt eines der benötigten Binaries (`netcrawler`, `result2csv`, `result2md`), bricht `netcrawl` mit einer klaren Fehlermeldung ab, die auf `make build` verweist, statt mit einem generischen "command not found".

Environment-Werte können für einen einzelnen Lauf überschrieben werden:

```bash
CONFIG=test.json RESULTS=test-results EXPORT=test-export ./netcrawl all
```

## Projektstruktur

```text
NetCrawl/
├── .env.example
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml     # gofmt, vet, Tests (mit PostgreSQL), E2E-Beleg, build
├── Makefile
├── README.md
├── go.mod
├── netcrawl
├── configs/
│   └── example.json
├── Dockerfile         # Image für netcrawl-server
├── deploy/
│   └── docker-compose.yml   # Server + PostgreSQL
├── cmd/
│   ├── netcrawl-agent/      # Crawler
│   ├── netcrawl-server/     # Server + Admin-Befehle
│   ├── netcrawler/
│   │   └── main.go
│   ├── result2csv/
│   │   └── main.go
│   └── result2md/
│       └── main.go
├── internal/
│   ├── agent/       # Crawler: Konfiguration, Vorabprüfung, Job-Prüfung
│   ├── config/      # Laden + Prüfen von config.json
│   ├── denylist/
│   ├── e2e/         # Abnahmetests (Loopback-Pilot, Inventar-Ablauf)
│   ├── eventlog/    # JSONL-Ereignislog, eine Datei pro Tag
│   ├── engine/      # Plan (/24-Jobs) und Scan-Ablauf
│   ├── envconfig/
│   ├── inventory/   # Baseline, neue/verschwundene Hosts, Port-Änderungen
│   ├── iprange/
│   ├── ports/       # Presets, Einzelports, Portbereiche
│   ├── protocol/    # Job-/Ergebnisformat, HMAC-Signatur
│   ├── result/
│   ├── scope/       # Freigabe: Allowlist, Hostlimit, private Bereiche
│   ├── server/      # HTTP-API (Crawler + Admin), Scheduler, Weboberfläche
│   ├── store/       # Datenhaltung: pgstore (PostgreSQL), memstore (Tests)
│   ├── version/
│   └── scanner/
│       ├── tcp/
│       └── probe/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── E2E-ABNAHME.md
│   ├── PROTOCOL.md
│   └── SERVER.md
├── results/       # generiert, nicht versioniert
└── export/        # generiert, nicht versioniert
```

## Git / lokale Daten

Folgende Daten gehören nicht ins Repository:

```text
.env
config.json
results/
export/
netcrawler
result2csv
result2md
```

Die Vorlagen `.env.example` und `configs/example.json` werden dagegen versioniert.

## Aktuelle Grenzen

Der MVP konzentriert sich auf IPv4 und TCP-Connect-Scanning. TLS-Zertifikate, HTTP-Titel/Server-Header und einfache Text-Banner werden für ausgewählte Standardports optional mit erfasst (siehe „Service-Erkennung“). Noch nicht Bestandteil des aktuellen Standes sind unter anderem IPv6, UDP-Scanning und eine vollständige Service-/Versionserkennung über beliebige Ports.

Diese Funktionen können später auf Basis des JSON-Datenmodells ergänzt werden.

## Sicherheit

NetCrawl ist für eigene oder ausdrücklich zum Scan freigegebene Netzwerke vorgesehen. Denylist und konfigurierbare Targets sollen helfen, den Scanbereich eindeutig einzugrenzen.

## Pfadauflösung und Validierung

Die CLI-Programme laden `.env` eigenständig. Explizite CLI-Parameter überschreiben Environment-Werte; Environment-Werte überschreiben die eingebauten Defaults.

Exporter unterscheiden zwischen Datei- und Verzeichnis-Input. Verzeichnis-Input verarbeitet alle `.json`-Ergebnisdateien und verlangt ein Ausgabe-Verzeichnis. Einzeldatei-Input erlaubt entweder ein Ausgabe-Verzeichnis oder eine explizite Zieldatei mit passender Endung. Dadurch werden Datei-/Verzeichnis-Verwechslungen früh erkannt.

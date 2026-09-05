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

## TCP Scanner

Der MVP verwendet einen parallelen TCP-Connect-Scan. Dadurch sind keine Raw Sockets und normalerweise keine Root-Rechte erforderlich.

Konfigurierbar sind insbesondere Port-Preset, zusätzliche Ports, Timeout und maximale Parallelität.

Über `ports.enabled` lässt sich der TCP-Scan vollständig deaktivieren (z. B. um Target-Auflösung und Denylist zu testen, ohne das Netz tatsächlich zu berühren). Ist der Wert `false`, werden keine Verbindungen aufgebaut; alle Hosts gelten als nicht responsive.

## Reverse DNS

Für Hosts mit gefundenen offenen Ports kann ein PTR-/Reverse-DNS-Lookup durchgeführt werden. Ein fehlender PTR-Eintrag ist kein Scanfehler.

## JSON-Ergebnis

Beispiel:

```json
{
  "schemaVersion": 1,
  "network": "192.168.1.0/24",
  "hosts": {
    "192.168.1.20": {
      "hostname": "server.local",
      "ports": [22, 80, 443]
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

Nur Hosts mit gefundenen offenen Ports erscheinen im aktuellen MVP als responsive Hosts.

## CSV Export

`result2csv` liest eine JSON-Datei oder ein Ergebnisverzeichnis.

```bash
./result2csv --input ./results --output ./export
```

Aus einem Ergebnisverzeichnis entstehen `all.csv` sowie einzelne Dateien pro `/24`.

Ein Host entspricht genau einer CSV-Zeile. Ports werden gemeinsam im Feld `ports` gespeichert.

Zeilen werden zunächst nach Netzwerk und dann nach IP-Adresse sortiert – numerisch, nicht als Text. `192.168.0.3` steht damit vor `192.168.0.102`, und `192.168.2.0/24` vor `192.168.10.0/24`.

## Markdown Export

`result2md` arbeitet analog:

```bash
./result2md --input ./results --output ./export
```

Es entstehen `all.md` und einzelne Reports pro `/24`.

Wie beim CSV-Export werden Netzwerke und IP-Adressen numerisch sortiert, nicht als Text.

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
├── README.md
├── go.mod
├── netcrawl
├── configs/
│   └── example.json
├── cmd/
│   ├── netcrawler/
│   │   └── main.go
│   ├── result2csv/
│   │   └── main.go
│   └── result2md/
│       └── main.go
├── internal/
│   ├── config/
│   ├── denylist/
│   ├── iprange/
│   ├── result/
│   └── scanner/
│       └── tcp/
├── docs/
│   └── ARCHITECTURE.md
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

Der MVP konzentriert sich auf IPv4 und TCP-Connect-Scanning. Noch nicht Bestandteil des aktuellen Standes sind unter anderem IPv6, UDP-Scanning, TLS-Metadaten, HTTP-Metadaten und detaillierte Service-/Versions-Erkennung.

Diese Funktionen können später auf Basis des JSON-Datenmodells ergänzt werden.

## Sicherheit

NetCrawl ist für eigene oder ausdrücklich zum Scan freigegebene Netzwerke vorgesehen. Denylist und konfigurierbare Targets sollen helfen, den Scanbereich eindeutig einzugrenzen.

## Pfadauflösung und Validierung

Die CLI-Programme laden `.env` eigenständig. Explizite CLI-Parameter überschreiben Environment-Werte; Environment-Werte überschreiben die eingebauten Defaults.

Exporter unterscheiden zwischen Datei- und Verzeichnis-Input. Verzeichnis-Input verarbeitet alle `.json`-Ergebnisdateien und verlangt ein Ausgabe-Verzeichnis. Einzeldatei-Input erlaubt entweder ein Ausgabe-Verzeichnis oder eine explizite Zieldatei mit passender Endung. Dadurch werden Datei-/Verzeichnis-Verwechslungen früh erkannt.

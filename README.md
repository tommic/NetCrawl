# Net Crawler MVP

Ein Go-basierter TCP-Connect-Scanner für eigene bzw. autorisierte Netze.

## Voraussetzungen

- Linux empfohlen
- Go 1.23+ zum Bauen

```bash
go version
```

Falls Go fehlt:

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install golang-go

# Fedora
sudo dnf install golang

# Arch Linux
sudo pacman -S go
```

## 1. `.env` einrichten

Zuerst die Environment-Vorlage kopieren:

```bash
cp .env.example .env
```

Standardinhalt:

```bash
CONFIG=config.json
RESULTS=results
EXPORT=export
```

Bedeutung:

- `CONFIG` – Pfad zur verwendeten Scan-Konfiguration.
- `RESULTS` – Verzeichnis für die JSON-Rohdaten des Scans.
- `EXPORT` – Zielverzeichnis für CSV- und Markdown-Exporte.

Die Werte werden vom `netcrawl`-Workflow verwendet. Ohne `.env` gelten dieselben Standardwerte.

`.env` wird nicht committed, `.env.example` dagegen schon.

## 2. `config.json` einrichten

Danach die Scan-Konfiguration kopieren:

```bash
cp configs/example.json config.json
```

In `config.json` werden Targets, Denylist, Ports, Timeouts und weitere Scan-Einstellungen festgelegt.

Insbesondere `targets.include` auf das eigene bzw. autorisierte Netz anpassen.

`config.json` wird nicht committed. `configs/example.json` dient als versionierte Vorlage.

## Build

```bash
go build -o netcrawler ./cmd/netcrawler
go build -o result2csv ./cmd/result2csv
go build -o result2md ./cmd/result2md
chmod +x netcrawl
```

## `netcrawler`

Start mit der Standardkonfiguration `./config.json`:

```bash
./netcrawler
```

Andere Konfiguration:

```bash
./netcrawler --config configs/meine-config.json
```

Parameter:

```text
--config <datei>    Pfad zur Scan-Konfiguration
                    Default: config.json
```

Die JSON-Ergebnisse werden entsprechend `output.directory` aus der Scan-Konfiguration geschrieben. Für den Standard-Workflow sollte dieses Verzeichnis mit `RESULTS` aus `.env` übereinstimmen.

## `result2csv`

Exportiert vorhandene JSON-Scanergebnisse als CSV.

Standard:

```bash
./result2csv
```

Explizit:

```bash
./result2csv --input ./results --output ./export
```

Parameter:

```text
--input <pfad>      JSON-Datei oder Verzeichnis mit JSON-Ergebnissen
                    Default: ./results

--output <ordner>   Zielverzeichnis
                    Default: ./export
```

Bei einem Ergebnisverzeichnis entstehen:

```text
export/
├── all.csv
├── 192.168.1.0_24.csv
├── 192.168.2.0_24.csv
└── ...
```

`all.csv` enthält alle Hosts. Zusätzlich wird pro `/24` eine CSV erzeugt.

Jeder Host steht genau einmal in der CSV. Die offenen Ports werden gemeinsam im Feld `ports` gespeichert.

## `result2md`

Exportiert vorhandene JSON-Scanergebnisse als Markdown.

Standard:

```bash
./result2md
```

Explizit:

```bash
./result2md --input ./results --output ./export
```

Parameter:

```text
--input <pfad>      JSON-Datei oder Verzeichnis mit JSON-Ergebnissen
                    Default: ./results

--output <ordner>   Zielverzeichnis
                    Default: ./export
```

Es entstehen:

```text
export/
├── all.md
├── 192.168.1.0_24.md
├── 192.168.2.0_24.md
└── ...
```

`all.md` enthält den gesamten Scan. Zusätzlich wird pro `/24` ein eigener Markdown-Report erzeugt.

## `netcrawl` Workflow

`netcrawl` lädt automatisch `.env`, falls die Datei vorhanden ist.

Kompletter Ablauf:

```bash
./netcrawl all
```

Entspricht:

```text
netcrawler
    ↓
RESULTS/*.json
    ↓
result2csv + result2md
    ↓
EXPORT/
```

Verfügbare Commands:

```bash
./netcrawl scan
./netcrawl csv
./netcrawl md
./netcrawl export
./netcrawl all
```

Bedeutung:

```text
scan      Nur Netzwerk-Scan ausführen.
csv       Nur CSV aus vorhandenen JSON-Ergebnissen erzeugen.
md        Nur Markdown aus vorhandenen JSON-Ergebnissen erzeugen.
export    CSV und Markdown aus vorhandenen JSON-Ergebnissen erzeugen.
all       Scan durchführen und anschließend CSV + Markdown erzeugen.
```

Die Pfade können auch temporär ohne Änderung der `.env` überschrieben werden:

```bash
CONFIG=test.json RESULTS=test-results EXPORT=test-export ./netcrawl all
```

Damit eignet sich derselbe Build beispielsweise für unterschiedliche Scan-Konfigurationen.

## Import und Export

Der Datenfluss ist bewusst getrennt:

```text
config.json
     │
     ▼
 netcrawler
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

Die JSON-Dateien unter `results/` sind damit das interne Austauschformat.

Die Exporter verändern die Scan-Ergebnisse nicht. Sie lesen vorhandene JSON-Dateien über `--input` ein und schreiben ihre Ausgabe über `--output`.

Dadurch können Exporte jederzeit erneut erzeugt werden, ohne das Netzwerk erneut zu scannen.

## Standard-Verzeichnisstruktur

```text
NetCrawl/
├── .env.example
├── .env                 # lokal, ignoriert
├── config.json          # lokal, ignoriert
├── configs/
│   └── example.json
├── results/             # JSON-Rohdaten, ignoriert
├── export/              # CSV/Markdown, ignoriert
├── netcrawler
├── result2csv
├── result2md
└── netcrawl
```

## Git

Nicht committed werden:

```text
.env
config.json
results/
export/
netcrawler
result2csv
result2md
```

## Hinweis

Nur in Netzen einsetzen, für die eine ausdrückliche Berechtigung zum Scannen besteht.

## Technische Dokumentation

Die Architektur und der Datenfluss sind ausführlicher in `docs/ARCHITECTURE.md` beschrieben.

## Parameter-Priorität und Datei-/Verzeichnisprüfung

Alle drei Programme laden `.env` selbst. Die Priorität ist:

```text
CLI-Parameter > Environment/.env > eingebauter Standard
```

Für `result2csv` und `result2md` gilt:

- Ist `--input` ein Verzeichnis, werden alle `.json`-Dateien darin verarbeitet. `--output` muss dann ein Verzeichnis sein bzw. wird als Verzeichnis angelegt.
- Ist `--input` eine einzelne `.json`-Datei, darf `--output` entweder ein Zielverzeichnis oder eine einzelne Datei mit passender Endung (`.csv` bzw. `.md`) sein.
- Existierende Pfade werden auf Datei/Verzeichnis geprüft.
- Falsche Dateiendungen oder widersprüchliche Kombinationen führen zu einer verständlichen Fehlermeldung.
- Bei Verzeichnis-Input entstehen immer `all.csv`/`all.md` und zusätzlich Dateien pro `/24`.

Beispiele:

```bash
./result2md
./result2md --input ./results --output ./export
./result2md --input ./results/192.168.0.0_24.json --output ./export
./result2md --input ./results/192.168.0.0_24.json --output ./report.md
```

# Net Crawler MVP

Ein kleiner Go-basierter TCP-Connect-Scanner für eigene bzw. autorisierte Netze.

## Voraussetzungen

- Go 1.23+
- Linux empfohlen

Zum Bauen muss Go auf dem Linux-System installiert sein. Prüfen:

```bash
go version
```

Falls `go` nicht gefunden wird, muss Go zuerst installiert werden. Je nach Distribution z. B.:

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install golang-go

# Fedora
sudo dnf install golang

# Arch Linux
sudo pacman -S go
```

Danach erneut mit `go version` prüfen.

## Konfiguration

Die mitgelieferte `configs/example.json` dient nur als Vorlage und bleibt im Repository.

Vor dem ersten Start eine eigene lokale Konfiguration anlegen:

```bash
cp configs/example.json configs/config.json
```

Danach `configs/config.json` bearbeiten und insbesondere `targets.include` auf das eigene bzw. autorisierte Netz anpassen.

Die lokalen Dateien unter `configs/` werden über `.gitignore` nicht committed. Nur `configs/example.json` wird versioniert.

Start mit der eigenen Konfiguration:

```bash
./netcrawler --config configs/config.json
```

Auch das Verzeichnis `results/` und `results.csv` werden ignoriert, damit Scan-Ergebnisse nicht versehentlich ins Git-Repository gelangen.

## Build

```bash
go build -o netcrawler ./cmd/netcrawler
```

## Start

Verwende eine Kopie von `configs/example.json` als lokale Konfiguration (siehe Abschnitt **Konfiguration**).

Die Ergebnisse landen pro `/24` unter `results/`.

## MVP-Funktionen

- IPv4, CIDR und `IP-IP` Targets
- Denylist mit denselben Formaten
- Gruppierung pro `/24`
- paralleler TCP-Connect-Scan
- Port-Presets plus Custom-Ports
- Reverse-DNS für Hosts mit offenen Ports
- atomare JSON-Ausgabe pro `/24`

## Hinweis

Nur in Netzen einsetzen, für die du eine ausdrückliche Berechtigung zum Scannen hast.


## JSON-Ergebnisse als CSV exportieren

Zum Projekt gehört das Tool `result2csv`. Es liest eine einzelne Ergebnis-JSON oder alle `.json`-Dateien eines Ergebnisverzeichnisses und erzeugt eine gemeinsame CSV-Datei.

Build:

```bash
go build -o result2csv ./cmd/result2csv
```

Komplettes Ergebnisverzeichnis exportieren:

```bash
./result2csv --input ./results --output ./results.csv
```

Eine einzelne `/24`-Ergebnisdatei exportieren:

```bash
./result2csv --input ./results/192.168.1.0_24.json --output ./network.csv
```

Die CSV enthält pro offenem Port eine Zeile:

```text
network,ip,hostname,port
192.168.1.0/24,192.168.1.20,server.local,22
192.168.1.0/24,192.168.1.20,server.local,80
```

## Standard-Workflow

Die Beispielkonfiguration zuerst kopieren:

```bash
cp configs/example.json config.json
```

`netcrawler` verwendet jetzt ohne Parameter automatisch `./config.json`.

```bash
./netcrawler
```

Alle Exporte landen standardmäßig unter `export/`. CSV und Markdown erzeugen jeweils eine Gesamtdatei und zusätzlich eine Datei pro `/24`:

```text
export/
├── all.csv
├── all.md
├── 192.168.1.0_24.csv
├── 192.168.1.0_24.md
└── ...
```

Kompletter Ablauf:

```bash
./netcrawl all
```

Einzelschritte:

```bash
./netcrawl scan
./netcrawl csv
./netcrawl md
./netcrawl export
```

`export` führt CSV und Markdown ohne neuen Scan aus. Die Verzeichnisse `results/`, `export/` sowie die lokale `config.json` werden nicht committed.

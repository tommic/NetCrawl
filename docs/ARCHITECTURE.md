# Net Crawler – Architektur und Projektkonzept

## 1. Ziel

Net Crawler ist ein Linux-orientiertes Werkzeug zur schnellen Inventarisierung von IPv4-Netzen, für die eine ausdrückliche Scan-Berechtigung besteht. Die Anwendung erhält ihre Arbeitsparameter aus einer JSON-Konfiguration, ermittelt erreichbare TCP-Dienste, versucht Reverse-DNS-Namen zu bestimmen und speichert die Ergebnisse getrennt pro `/24`-Netz.

Das Projekt ist bewusst modular angelegt. Der aktuelle MVP konzentriert sich auf einen TCP-Connect-Scan. HTTP-, TLS- und detaillierte Service-Erkennung sind als spätere Ausbaustufen vorgesehen.

## 2. Grundprinzip

Die Verarbeitung folgt dieser Pipeline:

```text
config.json
    |
    v
Config Parser / Validation
    |
    v
Target Parser
(IP / CIDR / IP-IP)
    |
    v
Denylist Filter
    |
    v
Gruppierung in /24 Network Jobs
    |
    v
Concurrent TCP Connect Scanner
    |
    v
Reverse DNS für gefundene Hosts
    |
    v
Result Collector
    |
    v
JSON pro /24
```

Ein `/24` ist die zentrale Ausgabeeinheit. Umgangssprachlich entspricht dies dem ursprünglich gewünschten „Class-C-Netz“, technisch verwendet das Projekt aber CIDR-Terminologie.

## 3. Konfiguration

`configs/example.json` ist die versionierte Vorlage. Lokale Konfigurationen werden nicht committed.

```bash
cp configs/example.json configs/config.json
```

### Targets

`targets.include` akzeptiert:

```text
192.168.1.10
192.168.1.0/24
192.168.1.10-192.168.1.50
```

`targets.deny` akzeptiert dieselben Formate. Ein Deny-Eintrag hat immer Vorrang vor einem Include-Eintrag.

### Ports

Der MVP unterstützt Port-Presets und zusätzliche Custom-Ports. Die Presets werden im Scanner definiert.

Aktuell vorgesehen:

- `tiny` – sehr kleine Auswahl wichtiger Ports
- `common` – typische Server- und Infrastrukturports
- `web` – typische HTTP-/HTTPS-Ports
- `database` – typische Datenbankports

Custom-Ports werden zum gewählten Preset hinzugefügt.

### Performance

`maxConcurrentConnections` bestimmt die maximale Zahl paralleler TCP-Connect-Versuche. `timeoutMs` begrenzt die Wartezeit je Verbindung.

Der MVP nutzt normale TCP-Connects und benötigt deshalb keine Raw-Sockets und üblicherweise keine Root-Rechte.

## 4. Target-Verarbeitung

IPv4-Adressen, CIDR-Netze und Bereiche werden in interne Adressbereiche überführt. Anschließend werden einzelne Zieladressen den jeweiligen `/24`-Netzen zugeordnet.

Mehrere Includes innerhalb desselben `/24` landen dadurch im selben logischen Ergebnisnetz. Doppelte IP-Adressen werden nur einmal verarbeitet.

IPv6 ist im aktuellen Stand nicht vorgesehen.

## 5. Denylist

Die Denylist wird vor dem Scan geprüft. Ausgeschlossene Adressen erzeugen keinen TCP-Scan.

Beispiele:

```text
192.168.1.1
192.168.10.0/24
10.0.0.20-10.0.0.50
```

Die Statistik des jeweiligen `/24` hält fest, wie viele Zieladressen aufgrund der Denylist ausgelassen wurden.

## 6. TCP-Scanner

Der MVP verwendet einen parallelen TCP-Connect-Scan. Für jede Kombination aus Ziel-IP und konfiguriertem Port wird ein Verbindungsversuch durchgeführt.

Ein erfolgreicher Connect bedeutet im MVP:

```text
TCP connection successful -> port open -> host relevant
```

Hosts ohne gefundenen offenen Port werden derzeit nicht in `hosts` gespeichert. Dadurch bleiben Ergebnisdateien kompakt.

Ein Host wird nicht ausschließlich aufgrund eines fehlgeschlagenen ICMP-Pings verworfen. Das ist eine bewusste Architekturentscheidung, weil viele Systeme ICMP blockieren.

## 7. Hostnamen

Für Hosts mit mindestens einem gefundenen offenen Port wird optional Reverse DNS durchgeführt.

```text
IP -> PTR lookup -> hostname/FQDN
```

Ein fehlender PTR-Eintrag verhindert nicht die Aufnahme des Hosts.

## 8. Ergebnisformat

Jedes bearbeitete `/24` erhält eine eigene JSON-Datei:

```text
results/
├── 192.168.1.0_24.json
├── 192.168.2.0_24.json
└── ...
```

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

Die Datei wird zunächst temporär geschrieben und anschließend umbenannt. Damit soll vermieden werden, dass eine teilweise geschriebene JSON-Datei als fertiges Ergebnis erscheint.

## 9. Exporter

### CSV

`result2csv` erzeugt genau eine Zeile pro Host. Alle Ports stehen gemeinsam in einem CSV-Feld.

```bash
go build -o result2csv ./cmd/result2csv
./result2csv --input ./results --output results.csv
```

Beispiel:

```csv
network,ip,hostname,ports
192.168.1.0/24,192.168.1.20,server.local,"22,80,443"
```

### Markdown

`result2md` erzeugt einen lesbaren Bericht mit einem Abschnitt pro `/24` und einer Tabelle der gefundenen Hosts.

```bash
go build -o result2md ./cmd/result2md
./result2md --input ./results --output results.md
```

Sowohl ein einzelnes JSON als auch ein Ergebnisverzeichnis können als Input verwendet werden.

## 10. Git und lokale Daten

Folgende Daten sollen nicht im Repository landen:

- lokale Konfigurationen
- Scan-Ergebnisse
- erzeugte Exporte
- lokal gebaute Binaries

`configs/example.json` ist ausdrücklich die einzige Konfiguration, die versioniert wird.

## 11. Projektstruktur

```text
NetCrawl/
├── cmd/
│   ├── netcrawler/
│   ├── result2csv/
│   └── result2md/
├── configs/
│   └── example.json
├── docs/
│   └── ARCHITECTURE.md
├── internal/
│   ├── config/
│   ├── denylist/
│   ├── iprange/
│   ├── result/
│   └── scanner/
│       └── tcp/
├── .gitignore
├── go.mod
└── README.md
```

## 12. Geplante Ausbaustufen

Nach dem MVP sind folgende Funktionen vorgesehen:

- Service-Erkennung auf offenen Ports
- optionale Versionsinformationen
- HTTP-Statuscode
- HTML-Seitentitel
- HTTP-Server-Header
- Redirect-Ziele
- TLS-Zertifikatsinformationen
- Common Name und SAN-Namen
- Zertifikatsaussteller und Ablaufdatum
- zusätzliche aus Zertifikaten gewonnene Hostnamen
- MAC-Adresse und Hersteller im direkt erreichbaren Layer-2-Netz
- Antwortzeiten
- `firstSeen` und `lastSeen`
- Scan-ID und Config-Hash
- Resume/Restart bereits abgeschlossener `/24`-Jobs
- Vergleich mehrerer Scans zur Erkennung von Änderungen
- optional weitere Port-Presets
- langfristig eventuell IPv6

## 13. Bewusste Designentscheidungen

### Go

Go wurde als guter Kompromiss aus Netzwerkperformance, Parallelität, einfacher Entwicklung und unkomplizierten Linux-Binaries gewählt.

### TCP Connect statt SYN Scan

Der MVP verwendet den normalen Netzwerkstack des Betriebssystems. Das vereinfacht Entwicklung und Betrieb und vermeidet Root-/Raw-Socket-Anforderungen.

### `/24` als Arbeitseinheit

Die Aufteilung hält Dateien klein, ermöglicht später Resume-Funktionen und erleichtert den Vergleich einzelner Netzsegmente.

### JSON als primäres Format

JSON bleibt das kanonische Maschinenformat. CSV und Markdown sind lediglich abgeleitete Exporte. Erweiterungen sollten deshalb zuerst im JSON-Datenmodell abgebildet und anschließend in den Exportern ergänzt werden.

## 14. Sicherheits- und Betriebsgrenze

Net Crawler ist für eigene Netze oder Umgebungen gedacht, für die eine ausdrückliche Berechtigung zum aktiven Scannen vorliegt. Hohe Parallelität kann Firewalls, IDS/IPS, Logging-Systeme oder schwache Netzwerkgeräte belasten. Deshalb sind Concurrency und Timeouts konfigurierbar.

## 15. Aktueller MVP-Status

Implementiert:

- JSON-Konfiguration
- IPv4 Einzeladressen
- CIDR
- IP-Ranges
- Denylist
- `/24`-Gruppierung
- Port-Presets
- Custom-Ports
- paralleler TCP-Connect-Scan
- Reverse DNS
- JSON-Ausgabe pro `/24`
- CSV-Export
- Markdown-Export

Noch nicht implementiert sind insbesondere HTTP-, TLS- und detaillierte Service-Erkennung sowie Resume und historische Scan-Vergleiche.

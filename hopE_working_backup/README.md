# hopE - Docker Compose Setup für ACA-Py Agenten

Dieses Setup stellt drei ACA-Py Agenten (Issuer, Holder, Verifier) bereit, die mit dem lokalen VON-Network verbunden sind.

## ✅ Status: Funktionsfähig

Alle drei Agenten laufen erfolgreich mit SQLite-basiertem Askar Storage.

## Übersicht

Das Setup basiert auf den Workflows aus dem `demo` Ordner und erstellt drei vollständige ACA-Py Agenten:

- **Issuer Agent** (Port 8020-8021): Entspricht "Faber" aus den Demos - gibt Credentials aus
- **Holder Agent** (Port 8030-8031): Entspricht "Alice" aus den Demos - empfängt und speichert Credentials
- **Verifier Agent** (Port 8040-8041): Entspricht "Acme" aus den Demos - verifiziert Presentations

## Voraussetzungen

1. **VON-Network muss laufen:**
   ```bash
   cd ../von-network
   ./manage start --wait
   ```

2. **Docker und Docker Compose** müssen installiert sein

3. **acapy-base Image** muss existieren:
   ```bash
   # Falls nicht vorhanden, im Hauptverzeichnis bauen:
   cd ..
   docker build -t acapy-base -f docker/Dockerfile .
   ```

## Architektur

```
┌─────────────────────────────────────────────────────────────┐
│                      hopE Network                            │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Issuer     │    │   Holder     │    │  Verifier    │  │
│  │   Agent      │    │   Agent      │    │   Agent      │  │
│  │  (Port 8020) │    │  (Port 8030) │    │  (Port 8040) │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                    │                    │          │
│  ┌──────▼───────┐    ┌──────▼───────┐    ┌──────▼───────┐  │
│  │   SQLite     │    │   SQLite     │    │   SQLite     │  │
│  │   Wallet     │    │   Wallet     │    │   Wallet     │  │
│  │  (Volume)    │    │  (Volume)    │    │  (Volume)    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                               │
└────────────────────────┬──────────────────────────────────-──┘
                         │
                         │ Connected to
                         │
                    ┌────▼─────┐
                    │   VON    │
                    │ Network  │
                    │(Port 9000│
                    └──────────┘
```

## Verwendung

### 1. Agenten starten

```bash
cd hopE
docker-compose up -d
```

### 2. Status überprüfen

```bash
# Alle Container anzeigen
docker-compose ps

# Logs eines spezifischen Agenten
docker-compose logs -f issuer
docker-compose logs -f holder
docker-compose logs -f verifier

# Health Status prüfen
curl http://localhost:8021/status/ready  # Issuer
curl http://localhost:8031/status/ready  # Holder
curl http://localhost:8041/status/ready  # Verifier
```

Alle Agenten sollten `{"ready": true}` zurückgeben.

### 3. Admin APIs verwenden

Die Admin APIs sind über folgende URLs erreichbar:

- **Issuer**: http://localhost:8021
- **Holder**: http://localhost:8031
- **Verifier**: http://localhost:8041

Swagger UI:
- Issuer: http://localhost:8021/api/doc
- Holder: http://localhost:8031/api/doc
- Verifier: http://localhost:8041/api/doc

### 4. Beispiel-Workflow

#### Schritt 1: Issuer registriert ein Schema und Credential Definition

```bash
# 1. Public DID für Issuer erstellen
curl -X POST "http://localhost:8021/wallet/did/create" \
  -H "Content-Type: application/json" \
  -d '{"method": "sov"}'

# Response enthält die DID, z.B.:
# {"result": {"did": "ABC123...", "verkey": "DEF456..."}}

# 2. DID auf dem Ledger registrieren (über VON-Network UI)
# Gehe zu: http://localhost:9000
# -> Authenticate a New DID
# -> Füge die DID und Verkey ein

# 3. DID als Public DID setzen
curl -X POST "http://localhost:8021/wallet/did/public?did=ABC123..."

# 4. Schema erstellen
curl -X POST "http://localhost:8021/schemas" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_name": "degree_schema",
    "schema_version": "1.0",
    "attributes": ["name", "degree", "date", "age"]
  }'

# 5. Credential Definition erstellen
curl -X POST "http://localhost:8021/credential-definitions" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_id": "<SCHEMA_ID_FROM_STEP_4>",
    "tag": "default",
    "support_revocation": false
  }'
```

#### Schritt 2: Connection zwischen Issuer und Holder herstellen

```bash
# 1. Issuer erstellt eine Invitation
curl -X POST "http://localhost:8021/out-of-band/create-invitation" \
  -H "Content-Type: application/json" \
  -d '{
    "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
    "use_public_did": false
  }'

# Response enthält die Invitation
# {"invitation": {...}, "invitation_url": "http://...?oob=..."}

# 2. Holder akzeptiert die Invitation
curl -X POST "http://localhost:8031/out-of-band/receive-invitation" \
  -H "Content-Type: application/json" \
  -d '<INVITATION_OBJECT_FROM_STEP_1>'

# 3. Connection ID notieren aus der Response
# Warte kurz, bis Connection "completed" Status hat
```

#### Schritt 3: Credential ausstellen

```bash
# Issuer sendet Credential Offer an Holder
curl -X POST "http://localhost:8021/issue-credential-2.0/send-offer" \
  -H "Content-Type: application/json" \
  -d '{
    "connection_id": "<CONNECTION_ID_FROM_STEP_2>",
    "filter": {
      "indy": {
        "cred_def_id": "<CRED_DEF_ID_FROM_STEP_1>"
      }
    },
    "credential_preview": {
      "@type": "issue-credential/2.0/credential-preview",
      "attributes": [
        {"name": "name", "value": "Alice Smith"},
        {"name": "degree", "value": "Bachelor of Science"},
        {"name": "date", "value": "2024-01-15"},
        {"name": "age", "value": "24"}
      ]
    }
  }'

# Holder akzeptiert automatisch (auto-store-credential: true)
# Credential wird im Wallet gespeichert
```

#### Schritt 4: Connection zwischen Holder und Verifier

```bash
# 1. Verifier erstellt eine Invitation
curl -X POST "http://localhost:8041/out-of-band/create-invitation" \
  -H "Content-Type: application/json" \
  -d '{
    "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
    "use_public_did": false
  }'

# 2. Holder akzeptiert die Invitation
curl -X POST "http://localhost:8031/out-of-band/receive-invitation" \
  -H "Content-Type: application/json" \
  -d '<INVITATION_OBJECT>'
```

#### Schritt 5: Proof Request und Verification

```bash
# 1. Verifier sendet Proof Request an Holder
curl -X POST "http://localhost:8041/present-proof-2.0/send-request" \
  -H "Content-Type: application/json" \
  -d '{
    "connection_id": "<CONNECTION_ID_HOLDER_VERIFIER>",
    "presentation_request": {
      "indy": {
        "name": "Proof of Degree",
        "version": "1.0",
        "requested_attributes": {
          "attr1_referent": {
            "name": "name",
            "restrictions": [{"cred_def_id": "<CRED_DEF_ID>"}]
          },
          "attr2_referent": {
            "name": "degree",
            "restrictions": [{"cred_def_id": "<CRED_DEF_ID>"}]
          }
        },
        "requested_predicates": {
          "predicate1_referent": {
            "name": "age",
            "p_type": ">=",
            "p_value": 18,
            "restrictions": [{"cred_def_id": "<CRED_DEF_ID>"}]
          }
        }
      }
    }
  }'

# 2. Holder muss die Presentation manuell senden (siehe Holder Admin API)
# 3. Verifier prüft die Presentation automatisch (auto-verify-presentation: true)
```

## Port-Übersicht

| Agent    | HTTP Port | Admin API | Storage    |
|----------|-----------|-----------|------------|
| Issuer   | 8020      | 8021      | SQLite     |
| Holder   | 8030      | 8031      | SQLite     |
| Verifier | 8040      | 8041      | SQLite     |

## Daten-Persistenz

Die Wallet-Daten werden in Docker Volumes gespeichert:
- `hope_issuer-data`: Issuer Wallet (SQLite)
- `hope_holder-data`: Holder Wallet (SQLite)
- `hope_verifier-data`: Verifier Wallet (SQLite)

## Agenten stoppen

```bash
# Alle Container stoppen (Daten bleiben erhalten)
docker-compose stop

# Alle Container und Volumes löschen (Daten werden gelöscht!)
docker-compose down -v

# Nur Container löschen, Volumes behalten
docker-compose down
```

## Troubleshooting

### Problem: Agenten können sich nicht mit VON-Network verbinden

**Lösung**: Stelle sicher, dass VON-Network läuft:
```bash
cd ../von-network
./manage start --wait
# Überprüfe: http://localhost:9000
```

### Problem: "Network von_von not found"

**Lösung**: Das VON-Network hat das externe Netzwerk nicht erstellt. Erstelle es manuell oder starte VON-Network neu:
```bash
docker network create von_von
# Oder:
cd ../von-network && ./manage down && ./manage start --wait
```

### Problem: "acapy-base image not found"

**Lösung**: Baue das Base-Image:
```bash
cd ..
docker build -t acapy-base -f docker/Dockerfile .
```

### Problem: Agents Exit mit Fehler

**Lösung**: Prüfe die Logs:
```bash
docker-compose logs issuer
docker-compose logs holder
docker-compose logs verifier
```

### Problem: "Port already in use"

**Lösung**: Andere Dienste blockieren die Ports. Entweder andere Dienste stoppen oder Ports in `docker-compose.yml` ändern.

## Technische Details

### Storage-Konfiguration

Die Agenten verwenden:
- **Wallet Type**: Askar (Aries-Askar)
- **Storage**: SQLite (im Docker Volume)
- **Persistence**: Alle Wallet-Daten bleiben bei Container-Neustart erhalten

### Auto-Accept Konfiguration

**Issuer**:
- `--auto-accept-invites`
- `--auto-accept-requests`
- `--auto-respond-credential-proposal`
- `--auto-respond-credential-offer`
- `--auto-respond-credential-request`
- `--auto-verify-presentation`

**Holder**:
- `--auto-accept-invites`
- `--auto-accept-requests`
- `--auto-respond-credential-offer`
- `--auto-store-credential`

**Verifier**:
- `--auto-accept-invites`
- `--auto-accept-requests`
- `--auto-verify-presentation`

### Netzwerk-Konfiguration

Die Agenten sind in zwei Netzwerken:
- `hope_network`: Internes Netzwerk für Kommunikation untereinander
- `von_von`: Externes Netzwerk für Verbindung zum VON-Network

## Konfiguration anpassen

Die Konfiguration kann über folgende Dateien angepasst werden:

1. **`.env`**: Umgebungsvariablen (URLs, Log-Level)
2. **`docker-compose.yml`**: Container-Konfiguration und ACA-Py Parameter

### Beispiel: Log-Level ändern

In `.env`:
```bash
LOG_LEVEL=debug
```

Dann Container neu starten:
```bash
docker-compose down
docker-compose up -d
```

## Weiterführende Dokumentation

- [ACA-Py Documentation](https://aca-py.org)
- [ACA-Py Admin API Reference](https://aca-py.org/main/api/)
- [VON Network GitHub](https://github.com/bcgov/von-network)
- [Hyperledger Aries RFCs](https://github.com/hyperledger/aries-rfcs)
- [Aries Askar](https://github.com/hyperledger/aries-askar)

## Demo-Scripts aus dem `demo` Ordner

Das Setup basiert auf den folgenden Demo-Workflows:
- `./demo/run_demo faber` → Issuer Agent
- `./demo/run_demo alice` → Holder Agent
- `./demo/run_demo acme` → Verifier Agent

Diese Python-basierten Demos bieten interaktive CLI-Interfaces für die Agenten und können parallel zu diesem Docker-Setup verwendet werden.

## Vergleich: Demo vs. hopE

| Feature | Demo (./demo/run_demo) | hopE (docker-compose) |
|---------|------------------------|------------------------|
| Start | Einzelne Prozesse | Docker Container |
| Storage | Temporär (in RAM) | Persistent (Volume) |
| Interface | CLI | REST API (Swagger) |
| Interaktiv | Ja | Nein |
| Production-ready | Nein | Ja |

## Lizenz

Dieses Setup ist Teil des MSc-blockchain-ssi-pqc Projekts.

## Änderungshistorie

- **2025-10-09**: Initiales Setup mit SQLite-Storage erstellt
- **2025-10-09**: Erfolgreiche Tests aller drei Agenten

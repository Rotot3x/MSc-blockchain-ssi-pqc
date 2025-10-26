# cheqd-node + ACA-Py SSI Integration Setup

Vollständige Self-Sovereign Identity (SSI) Testumgebung mit **Post-Quantum Cryptography** auf dem **cheqd Blockchain Ledger**.

## 🏗️ Architektur

### Komponenten

- **cheqd-node Localnet**: 4 Validatoren + 1 Seed + 1 Observer
- **DID Services**: Universal DID Resolver & Registrar für did:cheqd
- **PostgreSQL**: Wallet-Datenbank für alle ACA-Py Agenten
- **3 ACA-Py Agenten**:
  - **Issuer**: Stellt Credentials aus (mit PQC-Signaturen)
  - **Holder**: Empfängt und speichert Credentials
  - **Verifier**: Verifiziert Proofs

### Kryptographie

- **Signaturen**: ML-DSA-65 (NIST Post-Quantum, Level 3)
- **Verschlüsselung**: ML-KEM-768 (NIST Post-Quantum, Level 3)
- **Hybrid Mode**: PQC + klassische Kryptographie
- **DID Method**: did:cheqd mit PQC-Schlüsseln

## 📋 Voraussetzungen

### System Requirements

- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+
- **Speicher**: Mindestens 8 GB RAM
- **CPU**: 4+ Cores empfohlen
- **Festplatte**: 20 GB freier Speicher

### Software

```bash
# Docker & Docker Compose
docker --version  # >= 20.10
docker-compose --version  # >= 2.0

# Optional: jq für JSON-Verarbeitung
sudo apt-get install jq

# Optional: curl für API-Tests
sudo apt-get install curl

# Python für Jupyter Notebook
python3 --version  # >= 3.9
pip3 install jupyter requests
```

## 🚀 Schnellstart

### 1. Repository vorbereiten

```bash
cd /path/to/MSc-blockchain-ssi-pqc

# Environment-Datei erstellen
cp .env.cheqd.template .env.cheqd

# Skripte ausführbar machen
chmod +x scripts/*.sh
```

### 2. cheqd Network Configuration generieren

```bash
# Option A: Mit lokalem cheqd-noded Binary
cd cheqd-node/docker/localnet
./gen-network-config.sh "cheqd-local" 4 1 1

# Option B: Mit Docker (wenn kein lokales Binary)
docker run --rm -v $(pwd)/cheqd-node/docker/localnet:/workspace \\
  ghcr.io/cheqd/cheqd-node:latest \\
  /bin/bash -c "cd /workspace && ./gen-network-config.sh cheqd-local 4 1 1"

cd ../../..
```

### 3. Services starten

```bash
# Alle Services auf einmal starten
docker-compose -f docker-compose-cheqd-acapy.yml up -d

# ODER: Schritt für Schritt

# 1. cheqd Network starten
./scripts/start-cheqd-network.sh

# 2. Warten bis alle Services ready sind
./scripts/wait-for-services.sh

# 3. Agent DIDs initialisieren
./scripts/init-acapy-agents.sh
```

### 4. Jupyter Notebook ausführen

```bash
# Jupyter Notebook starten
jupyter notebook ssi_workflow_cheqd.ipynb

# Oder im Browser öffnen:
# http://localhost:8888
```

## 📡 Service Endpoints

### cheqd Network

| Service | Endpoint | Beschreibung |
|---------|----------|--------------|
| RPC | http://localhost:26657 | Tendermint RPC API |
| REST | http://localhost:1317 | Cosmos REST API |
| gRPC | localhost:9090 | gRPC Endpoint |
| DID Resolver | http://localhost:8080 | Universal DID Resolver |
| DID Registrar | http://localhost:9080 | Universal DID Registrar |

### ACA-Py Agents

| Agent | Admin API | Inbound Transport |
|-------|-----------|-------------------|
| Issuer | http://localhost:8021 | http://localhost:8020 |
| Holder | http://localhost:8031 | http://localhost:8030 |
| Verifier | http://localhost:8041 | http://localhost:8040 |

### Database

| Service | Endpoint |
|---------|----------|
| PostgreSQL | localhost:5432 |

## 📚 SSI Workflow

Das Jupyter Notebook führt durch den vollständigen SSI-Workflow:

### 1. Setup & Connectivity Tests
- cheqd Network Status prüfen
- ACA-Py Agent Status validieren
- DID Services testen

### 2. DID Management
- DIDs mit PQC-Schlüsseln erstellen (ML-DSA-65)
- DID Documents auf cheqd-Ledger veröffentlichen
- DID-Auflösung testen

### 3. Schema & Credential Definition
- AnonCreds Schema auf cheqd erstellen
- Credential Definition mit PQC-Signatur
- Optional: Revocation Registry einrichten

### 4. Connection Protocol
- DIDComm Connection: Issuer ↔ Holder
- DIDComm Connection: Holder ↔ Verifier

### 5. Credential Issuance
- Credential mit PQC-Signatur ausstellen
- Credential im Holder Wallet speichern
- Credential-Attribute validieren

### 6. Proof Presentation
- Proof Request vom Verifier
- Proof Präsentation vom Holder
- Zero-Knowledge Proof Verifikation

### 7. Revocation (Optional)
- Credential mit PQC-Signatur widerrufen
- Revocation Status prüfen

### 8. PQC Validation
- Post-Quantum Algorithmen validieren
- Sicherheitslevel verifizieren

## 🔧 Konfiguration

### Environment Variables

Wichtige Variablen in `.env.cheqd`:

```bash
# cheqd Fee Payer (für DID-Transaktionen)
FEE_PAYER_TESTNET_MNEMONIC="your-mnemonic-here"

# Wallet Keys (in Produktion ändern!)
ISSUER_WALLET_KEY=secure-key-here
HOLDER_WALLET_KEY=secure-key-here
VERIFIER_WALLET_KEY=secure-key-here

# PQC Configuration
PQC_ENABLED=true
PQC_SIGNATURE_ALGORITHM=ML-DSA-65
PQC_KEM_ALGORITHM=ML-KEM-768
PQC_HYBRID_MODE=true
```

### Agent Konfiguration

Agent-spezifische Konfiguration in `config/`:

- `config/issuer-config.yml` - Issuer Agent
- `config/holder-config.yml` - Holder Agent
- `config/verifier-config.yml` - Verifier Agent

### Plugin Konfiguration

- `config/cheqd-plugin-config.yml` - cheqd DID Method Plugin
- `config/pqc-plugin-config.yml` - Post-Quantum Crypto Plugin

## 🐛 Troubleshooting

### Services starten nicht

```bash
# Status prüfen
docker-compose -f docker-compose-cheqd-acapy.yml ps

# Logs anzeigen
docker-compose -f docker-compose-cheqd-acapy.yml logs [service]

# Services neu starten
docker-compose -f docker-compose-cheqd-acapy.yml restart [service]
```

### cheqd Network Probleme

```bash
# Network Config neu generieren
cd cheqd-node/docker/localnet
rm -rf network-config
./gen-network-config.sh "cheqd-local" 4 1 1

# Validatoren überprüfen
curl http://localhost:26657/status | jq
curl http://localhost:1317/cosmos/base/tendermint/v1beta1/node_info | jq
```

### ACA-Py Agent Fehler

```bash
# Agent Status prüfen
curl http://localhost:8021/status | jq  # Issuer
curl http://localhost:8031/status | jq  # Holder
curl http://localhost:8041/status | jq  # Verifier

# Wallet-Datenbank prüfen
docker exec -it postgres-acapy psql -U acapy -d acapy_wallets -c "\\l"

# Agent neu starten
docker-compose -f docker-compose-cheqd-acapy.yml restart acapy-issuer
```

### DID Services nicht erreichbar

```bash
# DID Resolver testen
curl http://localhost:8080/1.0/identifiers/did:cheqd:testnet:zF7rhDBfUt9d1gJPjx7s1J | jq

# DID Registrar testen
curl http://localhost:9080/1.0/methods | jq

# Services neu starten
docker-compose -f docker-compose-cheqd-acapy.yml restart did-resolver did-registrar
```

### Netzwerk-Probleme

```bash
# Docker-Netzwerk prüfen
docker network inspect cheqd-ssi-network

# DNS-Auflösung testen
docker exec acapy-issuer ping -c 3 cheqd-validator-0
docker exec acapy-issuer ping -c 3 postgres-acapy

# Firewall prüfen (Linux)
sudo ufw status
```

## 🧹 Cleanup

### Services stoppen

```bash
# Services stoppen (Daten bleiben erhalten)
docker-compose -f docker-compose-cheqd-acapy.yml stop

# Services stoppen und entfernen
docker-compose -f docker-compose-cheqd-acapy.yml down

# Alles entfernen inkl. Volumes (ACHTUNG: Löscht alle Daten!)
docker-compose -f docker-compose-cheqd-acapy.yml down -v
```

### Vollständiges Reset

```bash
# Alle Daten löschen
docker-compose -f docker-compose-cheqd-acapy.yml down -v
rm -rf cheqd-node/docker/localnet/network-config
rm -f .agent-dids

# Neu starten
./scripts/start-cheqd-network.sh
./scripts/wait-for-services.sh
./scripts/init-acapy-agents.sh
```

## 📊 Monitoring & Logs

### Alle Logs anzeigen

```bash
# Alle Services
docker-compose -f docker-compose-cheqd-acapy.yml logs -f

# Nur cheqd Network
docker-compose -f docker-compose-cheqd-acapy.yml logs -f cheqd-validator-0

# Nur ACA-Py Agents
docker-compose -f docker-compose-cheqd-acapy.yml logs -f acapy-issuer acapy-holder acapy-verifier
```

### Health Checks

```bash
# Automatischer Health Check aller Services
./scripts/wait-for-services.sh

# Manueller Health Check
curl http://localhost:26657/health  # cheqd RPC
curl http://localhost:8021/status/ready  # Issuer
curl http://localhost:8031/status/ready  # Holder
curl http://localhost:8041/status/ready  # Verifier
```

## 🔐 Sicherheit

### Produktion Best Practices

1. **Niemals Default-Passwörter verwenden**:
   ```bash
   # Starke Passwörter generieren
   openssl rand -base64 32
   ```

2. **Admin API absichern**:
   ```yaml
   # In config/*.yml
   admin-insecure-mode: false
   admin-api-key: your-secure-api-key
   ```

3. **TLS/SSL aktivieren**:
   - Zertifikate für alle Endpunkte
   - Nur HTTPS verwenden
   - Mutual TLS für Agent-Kommunikation

4. **Mnemonics sicher aufbewahren**:
   - Hardware Security Module (HSM)
   - Encrypted Vault (Hashicorp Vault)
   - Niemals in Version Control!

5. **Firewall konfigurieren**:
   ```bash
   # Nur notwendige Ports öffnen
   sudo ufw allow 26657/tcp  # RPC
   sudo ufw allow 1317/tcp   # REST API
   ```

## 📖 Weitere Ressourcen

### Dokumentation

- [cheqd Docs](https://docs.cheqd.io/)
- [ACA-Py Docs](https://aca-py.org/)
- [Hyperledger Aries RFCs](https://github.com/hyperledger/aries-rfcs)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

### Plugins

- [cheqd Plugin](https://github.com/openwallet-foundation/acapy-plugins/tree/main/cheqd)
- [PQCrypto_FM Plugin](../acapy-plugins/pqcrypto_fm/README.md)

### Community

- [OpenWallet Foundation](https://openwallet.foundation/)
- [Hyperledger Aries Discord](https://discord.gg/hyperledger)
- [cheqd Community](https://cheqd.io/community)

## 🤝 Beitragen

Contributions sind willkommen! Bitte beachten:

1. Fork das Repository
2. Feature Branch erstellen: `git checkout -b feature/amazing-feature`
3. Änderungen committen: `git commit -m 'Add amazing feature'`
4. Branch pushen: `git push origin feature/amazing-feature`
5. Pull Request erstellen

## 📄 Lizenz

Apache License 2.0 - siehe [LICENSE](LICENSE) Datei für Details.

## ✨ Danksagungen

- [cheqd Foundation](https://cheqd.io/) für das cheqd-node Projekt
- [OpenWallet Foundation](https://openwallet.foundation/) für ACA-Py
- [Open Quantum Safe](https://openquantumsafe.org/) für liboqs
- NIST für die Post-Quantum Cryptography Standardisierung

---

**Hinweis**: Dies ist eine Entwicklungs- und Testumgebung. Für Produktionsumgebungen sind zusätzliche Sicherheitsmaßnahmen erforderlich.

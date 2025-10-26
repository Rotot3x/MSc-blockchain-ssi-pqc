# cheqd + ACA-Py Post-Quantum SSI Integration

Vollständige Self-Sovereign Identity (SSI) Lösung mit **Post-Quantum Cryptography** auf dem **cheqd Blockchain Ledger**.

## 📦 Verzeichnisstruktur

```
cheqd-acapy-integration/
├── README.md                           # Diese Datei
├── README-CHEQD-SETUP.md              # Detaillierte Setup-Anleitung
├── docker-compose-cheqd-acapy.yml     # Docker Compose Orchestrierung
├── .env.cheqd.template                # Environment Template
├── ssi_workflow_cheqd.ipynb           # Jupyter Notebook für SSI Workflow
│
├── config/                            # Konfigurationsdateien
│   ├── issuer-config.yml             # Issuer Agent Konfiguration
│   ├── holder-config.yml             # Holder Agent Konfiguration
│   ├── verifier-config.yml           # Verifier Agent Konfiguration
│   ├── cheqd-plugin-config.yml       # cheqd Plugin Einstellungen
│   └── pqc-plugin-config.yml         # Post-Quantum Crypto Einstellungen
│
└── scripts/                           # Hilfsskripte
    ├── init-wallets.sql              # PostgreSQL Wallet Initialisierung
    ├── start-cheqd-network.sh        # cheqd Network starten
    ├── wait-for-services.sh          # Health Check aller Services
    └── init-acapy-agents.sh          # Agent DID Initialisierung
```

## 🚀 Schnellstart

### 1. Voraussetzungen

```bash
# Docker & Docker Compose installiert
docker --version  # >= 20.10
docker-compose --version  # >= 2.0

# Python & Jupyter für Notebook
python3 --version  # >= 3.9
pip3 install jupyter requests
```

### 2. Setup

```bash
# In diesen Ordner wechseln
cd cheqd-acapy-integration

# Environment-Datei erstellen
cp .env.cheqd.template .env.cheqd

# Skripte ausführbar machen
chmod +x scripts/*.sh
```

### 3. cheqd Network Config generieren

```bash
# Zurück zum Projekt-Root
cd ..

# Network Config generieren (wenn noch nicht vorhanden)
cd cheqd-node/docker/localnet
./gen-network-config.sh "cheqd-local" 4 1 1
cd ../../../cheqd-acapy-integration
```

### 4. Starten

```bash
# Alle Services starten
docker-compose -f docker-compose-cheqd-acapy.yml up -d

# Warten bis alle Services bereit sind
./scripts/wait-for-services.sh

# Agent DIDs initialisieren
./scripts/init-acapy-agents.sh

# Jupyter Notebook öffnen
jupyter notebook ssi_workflow_cheqd.ipynb
```

## 🏗️ Architektur

### Komponenten

- **6 cheqd-nodes**: 4 Validatoren + 1 Seed + 1 Observer
- **3 ACA-Py Agents**: Issuer, Holder, Verifier
- **DID Services**: Universal DID Resolver & Registrar
- **PostgreSQL**: Wallet-Datenbank für alle Agents

### Post-Quantum Cryptography

- **Signaturen**: ML-DSA-65 (NIST Level 3)
- **Verschlüsselung**: ML-KEM-768 (NIST Level 3)
- **Hybrid Mode**: PQC + klassische Kryptographie
- **DID Method**: did:cheqd mit PQC-Schlüsseln

## 📡 Service Endpoints

| Service | Endpoint | Beschreibung |
|---------|----------|--------------|
| cheqd RPC | http://localhost:26657 | Tendermint RPC API |
| cheqd REST | http://localhost:1317 | Cosmos REST API |
| DID Resolver | http://localhost:8080 | Universal DID Resolver |
| DID Registrar | http://localhost:9080 | Universal DID Registrar |
| Issuer Admin | http://localhost:8021 | Issuer Agent API |
| Holder Admin | http://localhost:8031 | Holder Agent API |
| Verifier Admin | http://localhost:8041 | Verifier Agent API |
| PostgreSQL | localhost:5432 | Wallet Database |

## 📚 Dokumentation

- **README-CHEQD-SETUP.md** - Detaillierte Setup-Anleitung mit Troubleshooting
- **ssi_workflow_cheqd.ipynb** - Interaktives Tutorial für den SSI Workflow

## 🔧 Konfiguration

### Environment Variables

Die wichtigsten Einstellungen in `.env.cheqd`:

```bash
# cheqd Fee Payer für DID-Transaktionen
FEE_PAYER_TESTNET_MNEMONIC="your-mnemonic"

# Wallet Keys (in Produktion ändern!)
ISSUER_WALLET_KEY=secure-key
HOLDER_WALLET_KEY=secure-key
VERIFIER_WALLET_KEY=secure-key

# PQC Einstellungen
PQC_ENABLED=true
PQC_SIGNATURE_ALGORITHM=ML-DSA-65
PQC_KEM_ALGORITHM=ML-KEM-768
```

## 🐛 Troubleshooting

### Services überprüfen

```bash
# Status aller Services
docker-compose -f docker-compose-cheqd-acapy.yml ps

# Logs anzeigen
docker-compose -f docker-compose-cheqd-acapy.yml logs -f [service]

# Services neu starten
docker-compose -f docker-compose-cheqd-acapy.yml restart
```

### Health Checks

```bash
# Automatischer Check aller Services
./scripts/wait-for-services.sh

# Manueller Check
curl http://localhost:26657/health  # cheqd
curl http://localhost:8021/status/ready  # Issuer
curl http://localhost:8031/status/ready  # Holder
curl http://localhost:8041/status/ready  # Verifier
```

## 🧹 Cleanup

```bash
# Services stoppen
docker-compose -f docker-compose-cheqd-acapy.yml down

# Alles löschen inkl. Volumes (ACHTUNG: Alle Daten gehen verloren!)
docker-compose -f docker-compose-cheqd-acapy.yml down -v
```

## 📖 Weiterführende Informationen

Siehe **README-CHEQD-SETUP.md** für:
- Detaillierte Installation
- SSI Workflow Beschreibung
- Erweiterte Konfiguration
- Sicherheits-Best-Practices
- Troubleshooting Guide

## 🤝 Support

Bei Fragen oder Problemen:
- Siehe README-CHEQD-SETUP.md für Troubleshooting
- Prüfe die Logs: `docker-compose logs`
- Verifiziere die Konfiguration in `config/`

## 📄 Lizenz

Apache License 2.0

---

**Status**: ✅ Production-Ready (mit entsprechenden Sicherheitsanpassungen)

**Version**: 1.0.0

**Letzte Aktualisierung**: 2025-09-30

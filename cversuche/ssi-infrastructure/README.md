# SSI Infrastructure with cheqd + ACA-Py

Complete Self-Sovereign Identity infrastructure with blockchain explorer for demonstration and development.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Jupyter Labs  │    │   DID Services  │
│   Notebooks     │    │   Resolver      │
│   :8888         │    │   :8080/:9080   │
└─────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────┬───────────┴────────────┘
                      │                       │
┌─────────────────────────────────────────────────────────────────┐
│                    cheqd Network (6 Nodes)                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │ Validator 0 │ │ Validator 1 │ │ Validator 2 │ │ Validator3│ │
│  │   :26657    │ │   :26757    │ │   :26857    │ │  :26957   │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
│  ┌─────────────┐ ┌─────────────┐                               │
│  │   Seed 0    │ │ Observer 0  │                               │
│  │   :27057    │ │   :27157    │                               │
│  └─────────────┘ └─────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ACA-Py        │    │   ACA-Py        │    │   ACA-Py        │
│   Issuer        │    │   Holder        │    │   Verifier      │
│   :8020/:8021   │    │   :8030/:8031   │    │   :8040/:8041   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   PostgreSQL    │
                    │   Databases     │
                    │   :5432/:5433   │
                    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Minimum 4GB RAM available
- Minimum 10GB disk space
- Ports 5432, 8020-8041, 8080, 8888, 9080, 26656-26957 available

### 1. Setup

```bash
cd ssi-infrastructure
./scripts/setup.sh
```

This will:
- Check system requirements
- Pull Docker images
- Generate secure passwords
- Validate configuration

### 2. Start Infrastructure

```bash
./scripts/start.sh
```

Wait for all services to become healthy (2-3 minutes).

### 3. Access Services

| Service | URL | Description |
|---------|-----|-------------|
| **Jupyter Labs** | http://localhost:8888 | SSI workflow demo |
| **DID Resolver** | http://localhost:8080 | DID resolution service |
| **DID Registrar** | http://localhost:9080 | DID registration service |
| **Issuer Admin** | http://localhost:8021 | ACA-Py Issuer API |
| **Holder Admin** | http://localhost:8031 | ACA-Py Holder API |
| **Verifier Admin** | http://localhost:8041 | ACA-Py Verifier API |

### 4. Run SSI Workflow Demo

1. Open Jupyter Labs: http://localhost:8888
2. Token: `ssi_workflow_secure_token_2024` (check `.env` file)
3. Open: `notebooks/ssi-workflow.ipynb`
4. Run all cells to execute the complete SSI workflow

### 5. Stop Infrastructure

```bash
./scripts/stop.sh
```

For complete cleanup (removes all data):
```bash
./scripts/stop.sh --cleanup
```

## 📋 Services Overview

### cheqd Network
- **6 Blockchain Nodes**: 4 validators, 1 seed, 1 observer
- **Consensus**: Tendermint with Ed25519 signatures
- **Chain ID**: `cheqd-ssi-local`
- **Native Token**: CHEQ
- **DID Method**: `did:cheqd` support

### ACA-Py Agents
- **3 Agents**: Issuer, Holder, Verifier
- **Wallet**: Askar-AnonCreds with PostgreSQL storage
- **Cryptography**: Classic Ed25519 (no Post-Quantum)
- **Protocols**: DIDComm, Issue Credential 2.0, Present Proof 2.0
- **Plugins**: cheqd DID method support


### Support Services
- **PostgreSQL**: Wallet storage for all agents
- **DID Resolver**: Universal DID resolution
- **DID Registrar**: DID creation and management
- **Jupyter Labs**: Interactive demo environment

## 🔧 Configuration

### Environment Variables (.env)

```bash
# Database Passwords
ACAPY_DB_PASSWORD=acapy_secure_password_2024
EXPLORER_DB_PASSWORD=bigdipper_secure_password_2024

# Service Secrets
HASURA_ADMIN_SECRET=hasura_admin_secret_2024
JUPYTER_TOKEN=ssi_workflow_secure_token_2024

# Network Configuration
CHEQD_CHAIN_ID=cheqd-ssi-local
```

### Agent Configuration

Each ACA-Py agent has its own configuration file:
- `config/acapy/issuer-config.yml`
- `config/acapy/holder-config.yml`
- `config/acapy/verifier-config.yml`

### cheqd Network Configuration

- `config/cheqd/genesis.json` - Network genesis file
- `config/cheqd/validators/` - Validator-specific configs

## 📊 SSI Workflow Demo

The Jupyter notebook demonstrates a complete SSI workflow:

### 1. Infrastructure Check
- Verify all services are running
- Check network connectivity
- Validate API endpoints

### 2. DID Management
- Create DIDs for all agents
- Use `did:cheqd` with Ed25519 keys
- Fallback to `did:key` if needed

### 3. Schema & Credential Definition
- Create AnonCreds schema on cheqd
- Define credential structure
- Set up credential definition with revocation

### 4. Connection Protocol
- Establish DIDComm connections
- Issuer ↔ Holder connection
- Holder ↔ Verifier connection

### 5. Credential Issuance
- Issue university diploma credential
- Include attributes: name, degree, university, GPA
- Sign with Ed25519 cryptography

### 6. Proof Presentation
- Request selective disclosure proof
- Verify GPA predicate (≥ 3.5)
- Validate zero-knowledge proof

### 7. Network Monitoring
- Query network statistics
- Monitor DID operations

## 🔍 Monitoring & Debugging

### Health Checks

```bash
# Check all container status
docker-compose ps

# Check specific service logs
docker-compose logs -f [service-name]

# Check agent status
curl http://localhost:8021/status  # Issuer
curl http://localhost:8031/status  # Holder
curl http://localhost:8041/status  # Verifier
```

### Common Service Ports

```
cheqd Network:
- 26657: Validator 0 RPC
- 1317:  Validator 0 REST API
- 9090:  Validator 0 gRPC

ACA-Py Agents:
- 8020/8021: Issuer (transport/admin)
- 8030/8031: Holder (transport/admin)
- 8040/8041: Verifier (transport/admin)

Support Services:
- 5432: ACA-Py PostgreSQL
- 8080: DID Resolver
- 8888: Jupyter Labs
- 9080: DID Registrar
```

### Troubleshooting

**Services not starting?**
- Check Docker daemon is running
- Ensure ports are not in use
- Check logs: `docker-compose logs [service]`

**Connection timeouts?**
- Wait for health checks to pass
- Check firewall settings
- Verify network connectivity

**Credential issuance failing?**
- Ensure DID creation succeeded
- Check schema/cred def creation
- Verify connection establishment


## 🛠️ Development

### Custom Configurations

1. Modify agent configs in `config/acapy/`
2. Update network settings in `config/cheqd/`

### Adding New Agents

1. Add service to `docker-compose.yml`
2. Create configuration file
3. Add database initialization
4. Update scripts and documentation

### Plugin Development

1. Mount plugin directory to agents
2. Update agent configuration
3. Add plugin dependencies
4. Test with demo workflow

## 📚 API Documentation

### ACA-Py Admin APIs
- **Issuer**: http://localhost:8021/api/doc
- **Holder**: http://localhost:8031/api/doc
- **Verifier**: http://localhost:8041/api/doc

### cheqd APIs
- **REST**: http://localhost:1317/swagger/
- **RPC**: http://localhost:26657/

### DID Services
- **Resolver**: http://localhost:8080/1.0/
- **Registrar**: http://localhost:9080/1.0/

### Explorer APIs
- **GraphQL**: http://localhost:8081/v1/graphql
- **Hasura Console**: http://localhost:8081/console

## 🔐 Security Notes

**Development Environment Only**
- Admin APIs have no authentication
- Default passwords are insecure
- Services use HTTP (not HTTPS)
- Debug logging is enabled

**Production Deployment**
- Enable API authentication
- Use strong passwords/secrets
- Configure HTTPS/TLS
- Set up proper firewalls
- Use production databases
- Enable audit logging

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test with demo workflow
5. Submit pull request

## 📝 License

This project is for educational and development purposes.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review service logs
3. Verify configuration
4. Open an issue with details

---

**Built with:**
- [cheqd-node](https://github.com/cheqd/cheqd-node) - Blockchain network
- [ACA-Py](https://github.com/openwallet-foundation/acapy) - SSI agent framework
- [PostgreSQL](https://postgresql.org/) - Database storage
- [Jupyter](https://jupyter.org/) - Interactive notebooks
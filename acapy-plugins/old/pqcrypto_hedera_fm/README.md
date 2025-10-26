# PQCrypto Hedera FM Plugin

## Description

This plugin provides complete Post-Quantum Cryptography (PQC) support for Self-Sovereign Identity (SSI) workflows on the Hedera Hashgraph network. It extends the existing `pqcrypto_fm` plugin to work seamlessly with Hedera's distributed ledger technology.

## Features

### Core PQC Support
- **Pure PQC Implementation**: No hybrid modes - 100% post-quantum cryptography
- **ML-DSA-65 Signatures**: NIST-standardized digital signatures
- **ML-KEM-768 Encryption**: NIST-standardized key encapsulation
- **liboqs Integration**: Built on Open Quantum Safe library

### DID Method: `did:hedera-pqc`
- **Format**: `did:hedera-pqc:network:pqc-identifier`
- **Example**: `did:hedera-pqc:testnet:z8mCrF2L9pQx7W3nK4mH8eR2vF9pL6uN`
- **Encoding**: MultiBase encoding of ML-DSA-65 public keys
- **Hedera Integration**: DIDs stored and resolved via Hedera consensus

### PQC-AnonCreds Alternative
- **PQC Schemas**: Schema registry on Hedera smart contracts
- **PQC Credential Definitions**: CredDef registry with ML-DSA-65 signatures
- **PQC Revocation**: Quantum-safe revocation mechanisms
- **PQC Proofs**: Zero-knowledge proofs with post-quantum security

### SSI Workflow
- **Complete PQC Issuer**: Issue credentials with pure PQC
- **Complete PQC Holder**: Store and present PQC credentials
- **Complete PQC Verifier**: Verify presentations with PQC algorithms
- **PQC-DIDComm v2**: Encrypted communication with ML-KEM-768

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PQC Agent     │    │  Hedera Ledger  │    │   PQC Holder    │
│   (Issuer)      │    │    Network      │    │    Agent        │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ pqcrypto_fm     │◄──►│ did:hedera-pqc  │◄──►│ pqcrypto_fm     │
│ + pqcrypto_hedera_fm │    │ PQC Schemas     │    │ + pqcrypto_hedera_fm │
│ Extension       │    │ PQC CredDefs    │    │ Extension       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites
- ACA-Py with `pqcrypto_fm` plugin
- Hedera Local Node or Hedera Testnet access
- Python 3.12+
- Node.js 20+ (for Hedera integration)

### Install Plugin
```bash
pip install -e ./acapy-plugins/pqcrypto_hedera_fm
```

### Configuration
```yaml
# pqcrypto-hedera-fm-config.yml
pqcrypto_hedera_fm:
  network: "testnet"  # or "mainnet", "local"
  operator_id: "0.0.12345"
  operator_key: "your-hedera-private-key"
  enable_pure_pqc: true
  disable_hybrid: true
  default_signature_algorithm: "ML-DSA-65"
  default_kem_algorithm: "ML-KEM-768"
```

## Usage

### Start ACA-Py with PQCrypto-Hedera-FM
```bash
aca-py start \
  --plugin pqcrypto_hedera_fm \
  --plugin pqcrypto_fm \
  --plugin-config pqcrypto-hedera-fm-config.yml \
  --arg-file pqcrypto-hedera-fm-agent.yml
```

### API Endpoints

#### DID Operations
- `POST /pqcrypto-hedera-fm/did/create` - Create did:hedera-pqc DID
- `GET /pqcrypto-hedera-fm/did/{did}` - Resolve PQC DID
- `POST /pqcrypto-hedera-fm/did/{did}/update` - Update DID document

#### Schema Operations
- `POST /pqcrypto-hedera-fm/schemas` - Create PQC schema
- `GET /pqcrypto-hedera-fm/schemas/{schema_id}` - Get PQC schema
- `GET /pqcrypto-hedera-fm/schemas` - List schemas

#### Credential Definition Operations
- `POST /pqcrypto-hedera-fm/credential-definitions` - Create PQC CredDef
- `GET /pqcrypto-hedera-fm/credential-definitions/{cred_def_id}` - Get CredDef

#### Credential Operations
- `POST /pqcrypto-hedera-fm/credentials/issue` - Issue PQC credential
- `POST /pqcrypto-hedera-fm/credentials/verify` - Verify PQC presentation

## Security

### Post-Quantum Algorithms
- **ML-DSA-65**: NIST FIPS 204 standardized
- **ML-KEM-768**: NIST FIPS 203 standardized
- **No Classical Crypto**: Pure post-quantum implementation
- **Quantum-Safe**: Protection against quantum computer attacks

### Hedera Security
- **Consensus Security**: Hashgraph consensus algorithm
- **Immutable Ledger**: Tamper-proof storage
- **Distributed Trust**: No single point of failure

## Development

### Project Structure
```
acapy-plugins/pqcrypto_hedera_fm/
├── pqcrypto_hedera_fm/
│   ├── v1_0/
│   │   ├── did/
│   │   │   ├── hedera_pqc_did_method.py
│   │   │   ├── hedera_pqc_resolver.py
│   │   │   └── hedera_pqc_registrar.py
│   │   ├── registry/
│   │   │   ├── pqc_anoncreds_registry.py
│   │   │   ├── pqc_schema_registry.py
│   │   │   └── pqc_creddef_registry.py
│   │   ├── services/
│   │   │   ├── hedera_client_service.py
│   │   │   ├── pqc_credential_service.py
│   │   │   └── pqc_verification_service.py
│   │   ├── routes/
│   │   │   ├── did_routes.py
│   │   │   ├── schema_routes.py
│   │   │   └── credential_routes.py
│   │   └── config.py
│   └── __init__.py
├── tests/
├── docs/
└── setup.py
```

## Standards Compliance

- **NIST PQC Standards**: ML-DSA (FIPS 204), ML-KEM (FIPS 203)
- **W3C VC Data Model 2.0**: With PQC signature suites
- **DIDComm v2**: With PQC encryption
- **ISO/IEC 23053**: Framework for PQC algorithms

## License

Apache License 2.0
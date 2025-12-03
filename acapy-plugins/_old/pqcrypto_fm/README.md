# PQCrypto_FM Plugin 🔐

**Post-Quantum Cryptography Plugin for ACA-Py with Automated liboqs Bundling**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![PQC Ready](https://img.shields.io/badge/PQC-Ready-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 🚀 What's New in v1.0

**Zero-configuration installation!** The plugin now automatically:
- ✅ Downloads and builds liboqs 0.14.0 during installation
- ✅ Bundles all quantum-resistant cryptographic libraries
- ✅ Works immediately after `pip install` - no manual setup required
- ✅ Supports Linux, macOS, and Windows

## 📖 Overview

PQCrypto_FM extends [ACA-Py](https://github.com/openwallet-foundation/acapy) with **Post-Quantum Cryptography** support for the complete Self-Sovereign Identity (SSI) lifecycle. Built on the [Open Quantum Safe (liboqs)](https://github.com/open-quantum-safe/liboqs) library, it provides quantum-resistant algorithms as the new cryptographic foundation for digital identity systems.

## Features

### 🔐 Post-Quantum Cryptography Support
- **NIST Standard Algorithms**: ML-DSA (Dilithium), ML-KEM (Kyber)
- **Additional PQC Algorithms**: Falcon, SPHINCS+, FrodoKEM, NTRU, SABER
- **Hybrid Cryptography**: Combines PQC with classical cryptography for enhanced security
- **liboqs Integration**: Uses the Open Quantum Safe library for algorithm implementations

### 🆔 PQC DID Methods
- **did:pqc**: Pure post-quantum DID method
- **did:hybrid**: Hybrid PQC+classical DID method
- **DID Documents**: W3C-compliant DID documents with PQC verification methods
- **Key Management**: Comprehensive PQC key lifecycle management

### 📜 PQC Verifiable Credentials
- **Credential Issuance**: Issue credentials with PQC signatures
- **Credential Verification**: Verify PQC-signed credentials
- **Hybrid Signatures**: Support for hybrid PQC+classical signatures
- **W3C Compliance**: Follows W3C Verifiable Credentials specification

### 🔧 Admin API Integration
- **REST Endpoints**: Full REST API for PQC operations
- **OpenAPI Documentation**: Swagger-documented API endpoints
- **Multi-tenant Support**: Works with ACA-Py's multi-tenant architecture

## Installation

### Prerequisites

1. **Python 3.12+**
2. **ACA-Py 1.3.2+**
3. **liboqs-python** (automatically installed)

### Install from Source

```bash
# Clone the plugin
git clone <plugin-repo-url>
cd pqcrypto_fm

# Install dependencies
pip install poetry
poetry install

# Or install directly
pip install -e .
```

### Install with ACA-Py

```bash
# Install the plugin alongside ACA-Py
pip install acapy-agent[aca-py]
pip install -e ./pqcrypto_fm
```

## Configuration

### Basic Configuration

Add to your ACA-Py configuration:

```yaml
# Enable the plugin
plugins:
  - pqcrypto_fm

# Plugin configuration
pqc:
  enable: true
  hybrid_mode: true
  set_as_default: true
  signature_algorithm: "ML-DSA-65"
  kem_algorithm: "ML-KEM-768"
```

### Advanced Configuration

```yaml
pqc:
  # Core settings
  enable: true
  hybrid_mode: true
  set_as_default: true

  # Algorithm preferences
  signature_algorithm: "ML-DSA-65"
  kem_algorithm: "ML-KEM-768"
  fallback_signature_algorithm: "Dilithium3"
  fallback_kem_algorithm: "Kyber768"

  # Performance settings
  enable_key_caching: true
  max_cached_keys: 100
  key_expiry_seconds: 3600

  # DID settings
  default_did_method: "did:hybrid"
  enable_did_pqc: true
  enable_did_hybrid: true

  # Credential settings
  enable_pqc_credentials: true
  enable_pqc_proofs: true

  # Debug settings
  debug_mode: false
  log_crypto_operations: false
```

### Command Line Options

```bash
# Start ACA-Py with PQC plugin
aca-py start \
  --plugin pqcrypto_fm \
  --plugin-config pqc.enable=true \
  --plugin-config pqc.hybrid_mode=true \
  --plugin-config pqc.set_as_default=true \
  --auto-provision \
  --inbound-transport http 0.0.0.0 8000 \
  --outbound-transport http \
  --admin 0.0.0.0 8001 --admin-insecure-mode \
  --genesis-transactions-list http://localhost:9000/genesis \
  --endpoint http://localhost:8000 \
  --wallet-type askar \
  --wallet-name acapy_pqc_wallet \
  --wallet-key key \
  --auto-accept-invites \
  --auto-accept-requests \
  --auto-ping-connection \
  --auto-respond-credential-proposal \
  --auto-respond-credential-offer \
  --auto-respond-credential-request \
  --auto-respond-presentation-proposal \
  --auto-respond-presentation-request \
  --auto-store-credential \
  --auto-verify-presentation
```

## Usage

### Key Management

#### Create PQC Keys

```bash
# Create a signature key
curl -X POST http://localhost:8001/pqcrypto_fm/keys \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "ml-dsa-65",
    "metadata": {"purpose": "signing"}
  }'

# Create a hybrid key
curl -X POST http://localhost:8001/pqcrypto_fm/keys \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "hybrid-ml-dsa-65-ed25519",
    "metadata": {"purpose": "hybrid-signing"}
  }'
```

#### List Keys

```bash
curl -X GET http://localhost:8001/pqcrypto_fm/keys
```

### DID Management

#### Create PQC DIDs

```bash
# Create a PQC DID
curl -X POST http://localhost:8001/pqcrypto_fm/dids \
  -H "Content-Type: application/json" \
  -d '{
    "method": "pqc",
    "key_type": "ml-dsa-65"
  }'

# Create a hybrid DID
curl -X POST http://localhost:8001/pqcrypto_fm/dids \
  -H "Content-Type: application/json" \
  -d '{
    "method": "hybrid",
    "key_type": "hybrid-ml-dsa-65-ed25519"
  }'
```

#### Get DID Document

```bash
curl -X GET http://localhost:8001/pqcrypto_fm/dids/{did}/document
```

### Signing and Verification

#### Sign Messages

```bash
curl -X POST http://localhost:8001/pqcrypto_fm/sign \
  -H "Content-Type: application/json" \
  -d '{
    "verkey": "your-verification-key",
    "message": "SGVsbG8gV29ybGQh"
  }'
```

#### Verify Signatures

```bash
curl -X POST http://localhost:8001/pqcrypto_fm/verify \
  -H "Content-Type: application/json" \
  -d '{
    "verkey": "verification-key",
    "message": "SGVsbG8gV29ybGQh",
    "signature": "signature-data",
    "algorithm": "ML-DSA-65"
  }'
```

### Get Available Algorithms

```bash
curl -X GET http://localhost:8001/pqcrypto_fm/algorithms
```

## Supported Algorithms

### Signature Algorithms

#### NIST Standard (Recommended)
- **ML-DSA-44**: NIST Level 1 security
- **ML-DSA-65**: NIST Level 3 security (default)
- **ML-DSA-87**: NIST Level 5 security

#### Additional Algorithms
- **Dilithium2, Dilithium3, Dilithium5**: Predecessor to ML-DSA
- **Falcon-512, Falcon-1024**: Lattice-based signatures
- **SPHINCS+**: Hash-based signatures (multiple variants)

### Key Encapsulation Mechanisms (KEM)

#### NIST Standard (Recommended)
- **ML-KEM-512**: NIST Level 1 security
- **ML-KEM-768**: NIST Level 3 security (default)
- **ML-KEM-1024**: NIST Level 5 security

#### Additional KEMs
- **Kyber512, Kyber768, Kyber1024**: Predecessor to ML-KEM
- **FrodoKEM**: Learning With Errors (LWE) based
- **NTRU**: Lattice-based KEM
- **SABER**: Module Learning With Errors based

### Hybrid Algorithms
- **Hybrid-ML-DSA-65-Ed25519**: ML-DSA + Ed25519
- **Hybrid-Dilithium3-Ed25519**: Dilithium + Ed25519
- **Hybrid-ML-KEM-768-X25519**: ML-KEM + X25519
- **Hybrid-Kyber768-X25519**: Kyber + X25519

## API Reference

### Endpoints

#### Algorithm Information
- `GET /pqcrypto_fm/algorithms` - Get available algorithms

#### Key Management
- `POST /pqcrypto_fm/keys` - Create a PQC key
- `GET /pqcrypto_fm/keys` - List PQC keys
- `DELETE /pqcrypto_fm/keys/{verkey}` - Delete a PQC key

#### Cryptographic Operations
- `POST /pqcrypto_fm/sign` - Sign a message
- `POST /pqcrypto_fm/verify` - Verify a signature

#### DID Management
- `POST /pqcrypto_fm/dids` - Create a PQC DID
- `GET /pqcrypto_fm/dids` - List PQC DIDs
- `GET /pqcrypto_fm/dids/{did}` - Get DID information
- `GET /pqcrypto_fm/dids/{did}/document` - Get DID document
- `DELETE /pqcrypto_fm/dids/{did}` - Delete a PQC DID

## Security Considerations

### ⚠️ Important Security Notes

1. **Experimental Algorithms**: Post-quantum algorithms are still being standardized and evaluated
2. **Hybrid Mode Recommended**: Use hybrid mode combining PQC with classical cryptography
3. **Key Management**: Properly secure and manage PQC private keys
4. **Algorithm Migration**: Be prepared to migrate to newer algorithms as standards evolve

### Best Practices

1. **Use NIST Standard Algorithms**: Prefer ML-DSA and ML-KEM over other algorithms
2. **Enable Hybrid Mode**: Combine PQC with classical cryptography for defense in depth
3. **Regular Updates**: Keep liboqs and the plugin updated
4. **Key Rotation**: Implement regular key rotation policies
5. **Monitoring**: Monitor cryptographic operations and performance

## Performance Considerations

### Algorithm Performance

- **ML-DSA**: Fast signing, moderate verification
- **Falcon**: Smaller signatures, slower operations
- **SPHINCS+**: Very secure but slower
- **ML-KEM/Kyber**: Fast key generation and encapsulation

### Optimization Tips

1. **Key Caching**: Enable key caching for frequently used keys
2. **Algorithm Selection**: Choose algorithms based on your performance requirements
3. **Hybrid Overhead**: Consider the overhead of hybrid operations
4. **Batch Operations**: Process multiple operations in batches when possible

## Development

### Testing

```bash
# Run tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=pqcrypto_fm

# Run integration tests
poetry run pytest integration/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Open Quantum Safe Project](https://openquantumsafe.org/) for liboqs
- [Hyperledger Aries](https://www.hyperledger.org/projects/aries) community
- [OpenWallet Foundation](https://openwallet.foundation/) for ACA-Py

## Support

For support and questions:

- Create an issue in this repository
- Join the OpenWallet Foundation Discord
- Participate in Hyperledger Aries community calls

## Roadmap

### Version 1.1
- [ ] Advanced credential formats (SD-JWT, AnonCreds)
- [ ] Revocation registries
- [ ] Performance optimizations

### Version 1.2
- [ ] Zero-knowledge proofs with PQC
- [ ] Advanced DID methods
- [ ] Cloud KMS integration

### Version 2.0
- [ ] New NIST algorithms as they are standardized
- [ ] Threshold signatures
- [ ] Advanced security features
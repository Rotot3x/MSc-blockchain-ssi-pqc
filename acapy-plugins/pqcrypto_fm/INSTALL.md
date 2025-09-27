# PQCrypto_FM Plugin Installation Guide

## 🚀 Automated Installation (Recommended)

The plugin now **automatically builds and bundles liboqs** during installation - no manual setup required!

### Simple pip Installation

```bash
pip install pqcrypto_fm
```

That's it! The plugin will:
- ✅ Automatically download liboqs source code
- ✅ Build liboqs with the correct configuration
- ✅ Bundle liboqs libraries with the plugin
- ✅ Work on Linux, macOS, and Windows

### Development Installation

```bash
git clone <repository>
cd pqcrypto_fm
pip install -e .
```

The automated build will run during installation.

## Running with ACA-Py

### Basic Usage

```bash
aca-py start --plugin pqcrypto_fm --plugin-config pqc.enable=true
```

### With Configuration File

Create a config file with:
```yaml
plugins:
  - pqcrypto_fm

pqc:
  enable: true
  hybrid_mode: true
  set_as_default: true
  signature_algorithm: "ML-DSA-65"
  kem_algorithm: "ML-KEM-768"
```

Then run:
```bash
aca-py start --arg-file config.yml
```

### Full Example with Faber Configuration

```bash
aca-py start \
  --plugin pqcrypto_fm \
  --plugin-config pqc.enable=true \
  --plugin-config pqc.hybrid_mode=true \
  --plugin-config pqc.set_as_default=true \
  --inbound-transport http 0.0.0.0 8020 \
  --outbound-transport http \
  --admin 0.0.0.0 8021 --admin-insecure-mode \
  --genesis-transactions-list http://localhost:9000/genesis \
  --endpoint http://localhost:8020 \
  --wallet-type askar \
  --wallet-name faber_pqc_wallet \
  --wallet-key faber_key \
  --auto-provision \
  --label "Faber PQC Agent" \
  --log-level info \
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

## Dependencies

The plugin automatically handles all dependencies:
- ✅ Python 3.12+ (required)
- ✅ liboqs 0.14.0 (automatically built and bundled)
- ✅ cryptography 41.0.0+ (automatically installed)
- ✅ ACA-Py 1.3.2+ (optional, install separately)

### Build Dependencies (automatically handled)
- cmake
- ninja (optional, but recommended)
- C compiler (gcc/clang/MSVC)

The plugin's setup script will check for these and provide helpful instructions if missing.

## Verifying Installation

After starting ACA-Py with the plugin, check the logs for:
```
🚀 Setting up PQCrypto_FM Plugin v1.0
✅ PQCrypto_FM Plugin v1.0 setup completed
```

You can also verify by calling the API:
```bash
curl http://localhost:8021/pqcrypto_fm/algorithms
```

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure the plugin is in Python path
2. **liboqs not found**: Install with `pip install liboqs-python`
3. **ACA-Py version**: Ensure you're using ACA-Py 1.3.2 or newer

### Debug Mode

Enable debug logging by adding:
```bash
--plugin-config pqc.debug_mode=true --log-level debug
```
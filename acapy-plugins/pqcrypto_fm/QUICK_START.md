# PQCrypto_FM Plugin - Quick Start Guide

## 🚀 Super Simple Installation

**No more manual liboqs installation needed!** The plugin now handles everything automatically.

### One-Command Installation

```bash
pip install pqcrypto_fm
```

That's it! The plugin will:
- ✅ Automatically download and build liboqs 0.14.0
- ✅ Bundle all necessary libraries
- ✅ Work immediately with ACA-Py

### Quick Test

```bash
# Start ACA-Py with the plugin
aca-py start --plugin pqcrypto_fm --plugin-config pqc.enable=true
```

You should see:
```
🚀 Setting up PQCrypto_FM Plugin v1.0
✅ Bundled liboqs successfully loaded
🔧 PQC Crypto Service initialized with 68 signature algorithms and 26 KEM algorithms
✅ PQCrypto_FM Plugin v1.0 setup completed
```

### Alternative: Development Installation

```bash
git clone <repository>
cd pqcrypto_fm
pip install -e .
```

The automated build runs during installation - no manual steps required!

## Verifying the Plugin Works

After installation, you should see these messages when starting ACA-Py:

```
🚀 Setting up PQCrypto_FM Plugin v1.0
✅ liboqs-python successfully loaded
🔧 PQC Crypto Service initialized with X signature algorithms and Y KEM algorithms
✅ PQCrypto_FM Plugin v1.0 setup completed
🔒 Hybrid mode enabled: PQC + Classical cryptography
⭐ PQC set as default cryptography for SSI operations
```

## Testing the API

Once running, test the PQC endpoints:

```bash
# Get available algorithms
curl http://localhost:8021/pqcrypto_fm/algorithms

# Expected response:
{
  "signature": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", ...],
  "kem": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", ...]
}
```

## Configuration Options

Add to your ACA-Py config:

```bash
--plugin pqcrypto_fm \
--plugin-config pqc.enable=true \
--plugin-config pqc.hybrid_mode=true \
--plugin-config pqc.set_as_default=true \
--plugin-config pqc.signature_algorithm=ML-DSA-65 \
--plugin-config pqc.kem_algorithm=ML-KEM-768 \
--plugin-config pqc.debug_mode=true
```

## Next Steps

1. **Install liboqs** using Option 1 above
2. **Test the plugin** with simulation mode first
3. **Try the demo** script: `python3 /home/ferris/github/acapy/demo/run_demo_pqc_full.py`
4. **Explore the API** endpoints for PQC operations

The plugin is now designed to fail gracefully and provide helpful guidance when liboqs is not available!
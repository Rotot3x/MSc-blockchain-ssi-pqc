# pqc_didpeer4_fm

**Post-Quantum did:peer:4 Plugin for ACA-Py**

Transparently replaces ED25519/X25519 with **ML-DSA-65** (NIST FIPS-204) and **ML-KEM-768** (NIST FIPS-203) in did:peer:4 DIDs.

## 🔐 Features

- ✅ **Post-Quantum Security**: ML-DSA-65 for signatures, ML-KEM-768 for key agreement
- ✅ **Transparent Integration**: NO API changes needed - works with existing workflows
- ✅ **Zero Code Changes**: Existing notebooks/scripts continue to work unchanged
- ✅ **Standards Compliant**: NIST FIPS-203/204, W3C Multicodec (provisional)
- ✅ **DIDComm v2 Ready**: Full encryption and authentication support

## 📦 Installation

```bash
cd acapy-plugins/pqc_didpeer4_fm
pip install -e .
```

## 🚀 Usage

### 1. Load Plugin in ACA-Py

```bash
aca-py start \
  --plugin pqc_didpeer4_fm \
  --endpoint https://agent.example.com:8020 \
  --admin 0.0.0.0 8021 \
  ...
```

### 2. docker-compose.yml

```yaml
services:
  issuer:
    command: >
      start
      --plugin pqc_didpeer4_fm  # ← Add this line
      --endpoint https://host.docker.internal:8020
      ...
```

### 3. Create Connection (Unchanged!)

```python
# Existing code continues to work!
invitation_data = {
    "use_did_method": "did:peer:4",  # ← Plugin makes this PQC automatically
    "handshake_protocols": ["https://didcomm.org/didexchange/1.1"],
    "my_label": "My Agent"
}

response = requests.post(
    "http://localhost:8021/out-of-band/create-invitation",
    json=invitation_data
)

# Plugin creates did:peer:4 with ML-DSA-65 + ML-KEM-768 automatically!
```

### 4. View DIDs

```python
# GET /wallet/did now shows PQC keys
response = requests.get("http://localhost:8021/wallet/did")

# Response:
# {
#   "results": [{
#     "did": "did:peer:4:z6MNxxx...",
#     "key_type": "ml-dsa-65",  # ← Shows PQC!
#     "method": "did:peer:4",
#     "metadata": {
#       "pqc_enabled": true,
#       "signature_algorithm": "ml-dsa-65",
#       "key_agreement_algorithm": "ml-kem-768",
#       "plugin": "pqc_didpeer4_fm"
#     }
#   }]
# }
```

## 🧬 How It Works

### Transparent Monkey-Patching

The plugin patches `BaseConnectionManager.create_did_peer_4()` at runtime:

```
Workflow: POST /out-of-band/create-invitation {"use_did_method": "did:peer:4"}
             ↓
         Out-of-Band Manager
             ↓
         BaseConnectionManager.create_did_peer_4()
             ↓
         🔄 PLUGIN INTERCEPTS HERE
             ↓
         Creates ML-DSA-65 + ML-KEM-768 keys instead of ED25519 + X25519
             ↓
         did:peer:4:z6MNxxx... (PQC enabled)
```

### Two Keys, Two Purposes

| Key Type | Purpose | DID Document Relationship |
|----------|---------|---------------------------|
| **ML-DSA-65** | Digital Signatures | `authentication`, `assertionMethod` |
| **ML-KEM-768** | Key Agreement (Encryption) | `keyAgreement` |

### Why Both?

- **ML-DSA-65** proves authenticity ("I am really Alice")
- **ML-KEM-768** enables encryption ("Only Bob can read this")
- **Both are required** for secure DIDComm messaging

## 🔧 Technical Details

### Multicodec Prefixes (Provisional)

- ML-DSA-65: `0xd065` → Multikey prefix `z6MN`
- ML-KEM-768: `0xe018` → Multikey prefix `z6MK768`

### Dependencies

- `aries-cloudagent~=1.0.0`
- `did-peer-4>=0.1.4`
- `pydid>=0.4.0`
- `multiformats>=0.3.0`
- `base58>=2.1.0`
- `pqcrypto_fm` (PQC crypto plugin - must be installed separately)

### Workflow Integration

**NO CODE CHANGES NEEDED!**

Existing workflows (e.g., `SSI_Complete_Workflow.ipynb` Cells 13-16) continue to work:

```python
# Cell 13 - Connection Creation (unchanged)
invitation_response = api_post(
    ISSUER_ADMIN_URL,
    "/out-of-band/create-invitation",
    {"use_did_method": "did:peer:4", ...}
)
# ✅ Plugin automatically uses ML-DSA-65 + ML-KEM-768

# Cell 16 - DID Overview (unchanged)
dids = api_get(ISSUER_ADMIN_URL, "/wallet/did")
# ✅ Shows "key_type": "ml-dsa-65" automatically
```

## ⚠️ Important Notes

1. **All agents must have the plugin**: If one agent has PQC enabled, all connected agents must also have it
2. **Not backward compatible**: Classic did:peer:4 (ED25519) and PQC did:peer:4 (ML-DSA-65) cannot interoperate
3. **Experimental**: PQC multicodec prefixes are provisional (W3C draft)
4. **Requires OpenSSL 3.5+**: For native ML-DSA/ML-KEM support

## 📚 References

- [NIST FIPS-203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS-204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [did:peer:4 Specification](https://identity.foundation/peer-did-method-spec/)
- [W3C Multicodec Registry](https://w3c-ccg.github.io/multicodec/)

## 📝 License

Apache License 2.0

## 👤 Author

Ferris Menzel

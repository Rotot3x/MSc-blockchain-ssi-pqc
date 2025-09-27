# PQCrypto_FM - Post-Quantum Cryptography Plugin for ACA-Py

Ein production-ready ACA-Py Plugin, das **Post-Quantum-Kryptographie (PQC)** über liboqs-python integriert und diese standardmäßig für **alle kryptographischen Verfahren** im gesamten SSI Workflow verwendet.

## 🎯 Übersicht

**PQCrypto_FM** (Post-Quantum Crypto - Future Mode) macht ACA-Py **quantum-safe** durch:

- ✅ **NIST-standardisierte PQC-Algorithmen**: ML-KEM, ML-DSA, SLH-DSA
- ✅ **Vollständige SSI-Integration**: Quantum-sichere DIDs, Credentials, Proofs
- ✅ **Hybrid-Kryptographie**: Kombination klassischer und PQC-Algorithmen  
- ✅ **Askar-AnonCreds Integration**: Optimiert für moderne ACA-Py Deployments
- ✅ **Demo-Kompatibilität**: Funktioniert mit `aca-py/demo/run_demo`
- ✅ **Production-Ready**: Umfassende Tests und Performance-Optimierungen

## 🚀 Installation

### 1. Voraussetzungen
```bash
# liboqs Installation (erforderlich für PQC-Algorithmen)
git clone https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
sudo cmake --build liboqs/build --target install
```

### 2. Plugin Installation
```bash
# In ACA-Py Plugins Repository
cd acapy-plugins
pip install ./pqcrypto_fm
```

### 3. ACA-Py Konfiguration
```yaml
# config.yml - Standard PQC-Konfiguration
label: quantum-safe-agent

wallet-type: askar-anoncreds
wallet-storage-type: default

plugin:
  - pqcrypto_fm.v1_0

plugin-config:
  pqcrypto_fm.v1_0:
    default_kem_algorithm: "Kyber768"
    default_sig_algorithm: "Dilithium3"
    hybrid_mode: true
    use_askar_anoncreds: true
```

## 🎮 Demo-Integration

```bash
# Demo mit PQC-Kryptographie starten
cd acapy/demo
python run_pqc_demo.py

# Alle Agenten verwenden jetzt quantum-sichere Kryptographie
```

## 📊 API-Integration

```bash
# PQC-Schlüssel generieren
curl -X POST "http://localhost:8021/pqc/keys/generate" \
  -H "Content-Type: application/json" \
  -d '{"key_type": "hybrid", "algorithm": "Kyber768"}'
```

## 📄 Lizenz

Apache License 2.0

---

**⚠️ Production Notice**: Dieses Plugin ist production-ready, jedoch wird für kritische Anwendungen ein umfassendes Security Audit empfohlen.

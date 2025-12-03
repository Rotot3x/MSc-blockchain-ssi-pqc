# PQCrypto_FM Plugin Troubleshooting

## Common Issues and Solutions

### 1. liboqs Installation Failure

**Error**:
```
liboqs not found, installing it in /home/vscode/_oqs
fatal: Remote branch 0.14.1 not found in upstream origin
Error installing liboqs.
RuntimeError: No oqs shared libraries found
```

**Solutions**:

#### Option A: Manual liboqs Installation (Recommended)

1. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential cmake ninja-build libssl-dev

   # macOS (with Homebrew)
   brew install cmake ninja openssl
   ```

2. **Install liboqs from source**:
   ```bash
   git clone -b main https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   mkdir build && cd build
   cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
   ninja
   sudo ninja install
   ```

3. **Install liboqs-python**:
   ```bash
   pip install liboqs-python
   ```

#### Option B: Use Pre-built Packages

1. **Install liboqs via package manager**:
   ```bash
   # Ubuntu 22.04+
   sudo apt-get install liboqs-dev

   # Or use conda
   conda install -c conda-forge liboqs
   ```

2. **Install liboqs-python**:
   ```bash
   pip install liboqs-python
   ```

#### Option C: Run in Simulation Mode

If you can't install liboqs, you can run the plugin in simulation mode:

```bash
aca-py start \
  --arg-file your-config.yml \
  --plugin pqcrypto_fm \
  --plugin-config pqc.enable=true \
  --plugin-config pqc.debug_mode=true
```

The plugin will load without actual PQC functionality but will show all the API endpoints and provide educational information.

### 2. Plugin Loading Issues

**Error**: `ModuleNotFoundError: No module named 'pqcrypto_fm'`

**Solution**:
```bash
cd /path/to/pqcrypto_fm
pip install -e .
```

### 3. Import Errors

**Error**: `ModuleNotFoundError: No module named 'acapy_agent'`

**Solution**: Make sure you're running from the correct ACA-Py environment:
```bash
# Check ACA-Py is installed
aca-py --version

# If not, install ACA-Py
pip install acapy-agent
```

### 4. Version Compatibility

**Error**: Various compatibility errors

**Solution**: Ensure you're using compatible versions:
- Python 3.12+
- ACA-Py 1.3.2+
- liboqs-python 0.14.0+

### 5. Docker Environment Issues

If running in Docker, you may need to install build tools:

```dockerfile
FROM python:3.12

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev \
    git

# Install liboqs
RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && \
    ninja install

# Install Python dependencies
RUN pip install liboqs-python acapy-agent

# Copy and install plugin
COPY pqcrypto_fm /app/pqcrypto_fm
RUN cd /app/pqcrypto_fm && pip install -e .
```

## Testing Installation

### 1. Test liboqs-python

```bash
python3 -c "
import oqs
print('liboqs-python version:', oqs.oqs.OQS_VERSION)
print('Available signature algorithms:', len(oqs.get_enabled_sig_mechanisms()))
print('Available KEM algorithms:', len(oqs.get_enabled_kem_mechanisms()))
"
```

### 2. Test Plugin Import

```bash
python3 -c "
import sys
sys.path.append('/path/to/acapy')
sys.path.append('/path/to/pqcrypto_fm')
import pqcrypto_fm.v1_0
print('Plugin import successful!')
"
```

### 3. Test ACA-Py with Plugin

```bash
aca-py start \
  --plugin pqcrypto_fm \
  --plugin-config pqc.enable=true \
  --plugin-config pqc.debug_mode=true \
  --help
```

Look for log messages like:
```
🚀 Setting up PQCrypto_FM Plugin v1.0
✅ liboqs-python successfully loaded
🔧 PQC Crypto Service initialized with X signature algorithms and Y KEM algorithms
✅ PQCrypto_FM Plugin v1.0 setup completed
```

## Performance Considerations

### Memory Usage
PQC algorithms typically use more memory:
- ML-DSA keys: ~2-4KB per key
- Classical keys: ~32-64 bytes per key

### Speed
PQC operations are slower:
- ML-DSA signing: ~10-100x slower than Ed25519
- ML-DSA verification: ~5-50x slower than Ed25519

## Getting Help

1. **Check logs**: Enable debug mode with `--plugin-config pqc.debug_mode=true`
2. **Test API**: `curl http://localhost:8021/pqcrypto_fm/algorithms`
3. **Open issues**: Report bugs at the plugin repository
4. **Community**: Join OpenWallet Foundation Discord

## Development Setup

For development and testing:

```bash
# Clone and setup
git clone <repo-url>
cd pqcrypto_fm

# Install in development mode
pip install -e .[dev]

# Run tests
pytest

# Run with specific ACA-Py version
pip install acapy-agent==1.3.2
aca-py start --plugin pqcrypto_fm
```
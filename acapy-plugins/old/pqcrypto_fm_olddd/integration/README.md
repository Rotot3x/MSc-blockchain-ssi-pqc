# Integration Tests for PQCrypto_FM Plugin

This directory contains comprehensive integration tests for the PQCrypto_FM plugin, ensuring quantum-safe cryptography works correctly across all ACA-Py workflows.

## 🧪 Test Structure

```
integration/
├── Dockerfile.test.runner     # Test runner container
├── docker-compose.yml        # Multi-agent test environment
├── pyproject.toml            # Test dependencies
├── poetry.lock               # Locked dependencies
└── tests/
    ├── __init__.py
    └── test_pqc_integration.py  # Main integration tests
```

## 🚀 Running Integration Tests

### Prerequisites
```bash
# Ensure Docker and Docker Compose are installed
docker --version
docker-compose --version

# Install Poetry for dependency management
pip install poetry
```

### Run All Tests
```bash
# From the integration directory
cd integration
docker-compose up --build

# Run specific test suites
docker-compose run test-runner pytest -v -k "test_pqc"
docker-compose run test-runner pytest -v -k "test_demo"
```

### Run Tests Locally
```bash
# Install test dependencies
poetry install

# Run tests with liboqs available
poetry run pytest tests/ -v --tb=short

# Run with coverage
poetry run pytest tests/ --cov=pqcrypto_fm --cov-report=html
```

## 🎯 Test Coverage

### Core PQC Functionality
- ✅ **Algorithm Availability**: Test all NIST-standardized algorithms
- ✅ **Key Generation**: KEM, Signature, and Hash-based keys  
- ✅ **Crypto Operations**: Encrypt/Decrypt, Sign/Verify
- ✅ **Hybrid Cryptography**: PQC + Classical combinations
- ✅ **Askar Integration**: Wallet storage and retrieval

### SSI Workflow Integration
- ✅ **Connection Establishment**: Quantum-safe DIDComm
- ✅ **Credential Issuance**: PQC-signed credentials
- ✅ **Proof Presentation**: Quantum-safe proofs
- ✅ **Multi-Agent**: Faber-Alice-Acme scenarios

### Demo Compatibility
- ✅ **run_demo Integration**: Works with ACA-Py demos
- ✅ **Performance Testing**: PQC vs Classical benchmarks
- ✅ **Agent Configurations**: Faber, Alice, Acme, Performance

### Error Handling & Edge Cases
- ✅ **Algorithm Fallbacks**: Graceful degradation
- ✅ **Configuration Validation**: Invalid settings handling  
- ✅ **Network Failures**: Resilient operation
- ✅ **Key Management**: Rotation and cleanup

## 📊 Test Scenarios

### 1. Basic PQC Operations
```python
async def test_pqc_key_generation():
    """Test generation of all PQC key types."""
    
async def test_hybrid_encryption():
    """Test hybrid PQC+Classical encryption."""
    
async def test_signature_verification():
    """Test PQC digital signatures."""
```

### 2. Multi-Agent Scenarios
```python
async def test_quantum_safe_connection():
    """Test PQC connection between agents."""
    
async def test_pqc_credential_flow():
    """Test end-to-end credential issuance with PQC."""
    
async def test_performance_comparison():
    """Compare PQC vs Classical performance."""
```

### 3. Demo Integration
```python
async def test_demo_with_pqc():
    """Test complete demo workflow with PQC enabled."""
    
async def test_faber_alice_acme_pqc():
    """Test three-agent demo with quantum-safe crypto."""
```

## 🐳 Docker Test Environment

### Test Runner Configuration
```dockerfile
FROM ghcr.io/openwallet-foundation/acapy:py3.12-1.3-lts

# Install liboqs and test dependencies
RUN apt-get update && apt-get install -y liboqs-dev
COPY pyproject.toml poetry.lock ./
RUN poetry install

# Copy PQCrypto_FM plugin
COPY ../pqcrypto_fm ./pqcrypto_fm
RUN pip install -e .

# Run tests
CMD ["poetry", "run", "pytest", "-v"]
```

### Multi-Agent Test Setup
```yaml
# docker-compose.yml
version: '3.8'

services:
  # Test agents
  alice:
    image: pqcrypto-fm:test
    environment:
      AGENT_NAME: alice
      ACAPY_PLUGIN: pqcrypto_fm.v1_0
      
  faber:
    image: pqcrypto-fm:test  
    environment:
      AGENT_NAME: faber
      ACAPY_PLUGIN: pqcrypto_fm.v1_0
      
  acme:
    image: pqcrypto-fm:test
    environment:
      AGENT_NAME: acme  
      ACAPY_PLUGIN: pqcrypto_fm.v1_0
      
  # Test runner
  test-runner:
    image: pqcrypto-fm:test
    depends_on: [alice, faber, acme]
    command: ["pytest", "-v", "tests/"]
```

## 🔧 Test Configuration

### Algorithm Testing Matrix
| **Test Case** | **KEM** | **Signature** | **Security Level** |
|---------------|---------|---------------|-------------------|
| Fast Tests | Kyber512 | Dilithium2 | Level 1 |
| Standard Tests | Kyber768 | Dilithium3 | Level 3 |
| Security Tests | Kyber1024 | Dilithium5 | Level 5 |
| Hybrid Tests | Kyber768+ECDH | Dilithium3+RSA | Mixed |

### Performance Benchmarks
```python
PERFORMANCE_TARGETS = {
    "key_generation": {"pqc": 10.0, "hybrid": 12.0},  # ms
    "signing": {"pqc": 50.0, "hybrid": 55.0},         # ms  
    "verification": {"pqc": 15.0, "hybrid": 17.0},    # ms
    "encryption": {"pqc": 5.0, "hybrid": 7.0},        # ms
}
```

## 📈 Continuous Integration

### GitHub Actions Workflow
```yaml
name: PQCrypto_FM Integration Tests

on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install liboqs
      run: |
        sudo apt-get update
        sudo apt-get install -y liboqs-dev
        
    - name: Run Integration Tests
      run: |
        cd integration
        docker-compose up --build --exit-code-from test-runner
        
    - name: Upload Coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./integration/coverage.xml
```

## 🚨 Known Test Limitations

### Environment Dependencies
- **liboqs Availability**: Tests require liboqs-python to be available
- **Hardware Features**: Some optimizations require specific CPU features
- **Network Connectivity**: Demo tests need internet access for ledger

### Performance Considerations  
- **Resource Usage**: PQC tests use more CPU and memory than classical
- **Test Duration**: Full integration tests can take 10-15 minutes
- **Parallel Execution**: Limited by system resources

## 🔍 Debugging Tests

### Verbose Output
```bash
# Enable detailed logging
docker-compose run test-runner pytest -v -s --log-cli-level=DEBUG

# Test specific scenarios
docker-compose run test-runner pytest -k "test_demo" -v --tb=long
```

### Test Data Inspection
```bash
# Access test containers
docker-compose exec alice bash
docker-compose exec test-runner bash

# Check logs
docker-compose logs alice
docker-compose logs test-runner
```

## 🎯 Contributing Tests

1. **Add New Test Cases**: Follow existing patterns in `test_pqc_integration.py`
2. **Update Test Matrix**: Add new algorithm combinations
3. **Performance Tests**: Include benchmarks for new features
4. **Documentation**: Update test descriptions and expected results

### Test Writing Guidelines
```python
@pytest.mark.asyncio
@pytest.mark.pqc
async def test_new_pqc_feature():
    """Test description with expected behavior."""
    # Arrange
    setup_test_environment()
    
    # Act  
    result = await perform_pqc_operation()
    
    # Assert
    assert result.is_quantum_safe()
    assert result.performance_acceptable()
```

---

**📝 Note**: These integration tests ensure PQCrypto_FM works correctly across all supported environments and use cases. Regular execution helps maintain quantum-safe reliability as the plugin evolves.
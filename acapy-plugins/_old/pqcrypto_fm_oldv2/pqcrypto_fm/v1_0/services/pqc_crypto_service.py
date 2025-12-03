"""
PQC Cryptographic Service

Simplified crypto service using liboqs-python.
"""

import logging
from dataclasses import dataclass

try:
    import oqs
    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False

LOGGER = logging.getLogger(__name__)

@dataclass
class PQCKeyPair:
    """PQC key pair container."""
    public_key: bytes
    private_key: bytes
    algorithm: str
    key_type: str

@dataclass
class HybridSharedSecret:
    """Hybrid shared secret container."""
    pqc_secret: bytes
    classical_secret: bytes
    combined_secret: bytes

class PQCCryptoService:
    """Post-Quantum Cryptography service."""

    def __init__(self, config):
        self.config = config
        self._initialized = False

        if not HAS_LIBOQS:
            LOGGER.warning("❌ liboqs-python not available")

    async def initialize(self):
        """Initialize the crypto service."""
        if not HAS_LIBOQS:
            LOGGER.warning("⚠️ PQC functionality limited without liboqs-python")
            return

        LOGGER.info("🔧 Initializing PQC Crypto Service...")
        self._initialized = True
        LOGGER.info("✅ PQC Crypto Service initialized")

    def generate_kem_keypair(self, algorithm=None):
        """Generate a PQC KEM key pair."""
        if not HAS_LIBOQS:
            raise RuntimeError("liboqs-python not available")

        algorithm = algorithm or self.config.default_kem_algorithm
        kem = oqs.KeyEncapsulation(algorithm)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        return PQCKeyPair(
            public_key=public_key,
            private_key=private_key,
            algorithm=algorithm,
            key_type="kem"
        )

    def get_available_algorithms(self):
        """Get available PQC algorithms."""
        if not HAS_LIBOQS:
            return {"kem": [], "signature": []}

        return {
            "kem": ["Kyber512", "Kyber768", "Kyber1024"],
            "signature": ["Dilithium2", "Dilithium3", "Dilithium5"]
        }
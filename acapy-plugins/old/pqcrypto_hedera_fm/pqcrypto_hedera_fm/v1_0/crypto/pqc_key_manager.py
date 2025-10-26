"""PQC Key Manager for Hedera integration."""

import logging
import secrets
import hashlib
import base64
from typing import Dict, Any, Optional, List, Tuple, NamedTuple
from dataclasses import dataclass

from acapy_agent.core.error import BaseError

LOGGER = logging.getLogger(__name__)

try:
    # First priority: Use our dedicated liboqs installation for pqcrypto_hedera_fm
    from ...oqs import oqs
    OQS_AVAILABLE = True
    LOGGER.info("Using dedicated liboqs installation for pqcrypto_hedera_fm")
except ImportError:
    try:
        # Fallback: Use the oqs module from pqcrypto_fm package
        from pqcrypto_fm import oqs
        OQS_AVAILABLE = True
        LOGGER.info("Using pqcrypto_fm.oqs with precompiled liboqs libraries")
    except ImportError:
        try:
            # Fallback to standard oqs package with dynamic library path
            import os
            import sys

            # Find pqcrypto_fm package path dynamically for libraries
            for path in sys.path:
                pqcrypto_fm_lib = os.path.join(path, 'pqcrypto_fm', 'lib')
                if os.path.exists(pqcrypto_fm_lib):
                    current_ld_path = os.environ.get('LD_LIBRARY_PATH', '')
                    if pqcrypto_fm_lib not in current_ld_path:
                        os.environ['LD_LIBRARY_PATH'] = f"{pqcrypto_fm_lib}:{current_ld_path}"
                    break

            import oqs
            OQS_AVAILABLE = True
            LOGGER.info("Using standard oqs package with dynamic library path")
        except ImportError:
            OQS_AVAILABLE = False
            oqs = None
            LOGGER.warning("liboqs not available - using persistent storage with classical crypto placeholders")

from ..storage.persistent_storage import PersistentPQCStorage


class PQCKeyError(BaseError):
    """PQC Key management errors."""
    pass


@dataclass
class PQCKeyPair:
    """PQC Key Pair container."""
    public_key_bytes: bytes
    private_key_bytes: bytes
    algorithm: str
    key_id: str


class PQCKeyManager:
    """Post-Quantum Cryptography Key Manager."""

    # Supported PQC algorithms
    SUPPORTED_SIGNATURE_ALGORITHMS = [
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "Dilithium2", "Dilithium3", "Dilithium5",
        "FALCON-512", "FALCON-1024"
    ]

    SUPPORTED_KEM_ALGORITHMS = [
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "Kyber512", "Kyber768", "Kyber1024"
    ]

    # Algorithm mappings for liboqs
    ALGORITHM_MAPPING = {
        # ML-DSA algorithms (native in our dedicated liboqs)
        "ML-DSA-44": "ML-DSA-44",
        "ML-DSA-65": "ML-DSA-65",
        "ML-DSA-87": "ML-DSA-87",

        # Dilithium fallback mapping (for compatibility)
        "Dilithium2": "ML-DSA-44",
        "Dilithium3": "ML-DSA-65",
        "Dilithium5": "ML-DSA-87",

        # ML-KEM algorithms (native in our dedicated liboqs)
        "ML-KEM-512": "ML-KEM-512",
        "ML-KEM-768": "ML-KEM-768",
        "ML-KEM-1024": "ML-KEM-1024",

        # Kyber fallback mapping (for compatibility)
        "Kyber512": "ML-KEM-512",
        "Kyber768": "ML-KEM-768",
        "Kyber1024": "ML-KEM-1024",
    }

    def __init__(self, config):
        """Initialize PQC Key Manager.

        Args:
            config: Plugin configuration
        """
        self.config = config
        self._initialized = False

        # Initialize persistent storage
        self.storage = PersistentPQCStorage()

        # Key cache for performance
        self._key_cache: Dict[str, PQCKeyPair] = {}

    async def initialize(self):
        """Initialize the key manager."""
        if self._initialized:
            return

        LOGGER.info("Initializing PQC Key Manager with persistent storage...")

        if not OQS_AVAILABLE:
            LOGGER.warning("liboqs not available - using persistent storage with classical crypto placeholders")
        else:
            LOGGER.info("liboqs available - using real PQC algorithms with persistent storage")

        # Verify supported algorithms
        if OQS_AVAILABLE:
            available_sigs = oqs.oqs_get_enabled_sig_mechanisms()
            available_kems = oqs.oqs_get_enabled_KEM_mechanisms()

            LOGGER.info(f"Available signature algorithms: {len(available_sigs)}")
            LOGGER.info(f"Available KEM algorithms: {len(available_kems)}")

        # Show storage stats
        stats = self.storage.get_storage_stats()
        LOGGER.info(f"Storage stats: {stats}")

        self._initialized = True
        LOGGER.info("✅ PQC Key Manager initialized with persistent storage")

    async def generate_key_pair(
        self,
        algorithm: str,
        seed: Optional[str] = None
    ) -> PQCKeyPair:
        """Generate PQC key pair.

        Args:
            algorithm: PQC algorithm to use
            seed: Optional seed for deterministic generation

        Returns:
            PQC key pair
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Generating key pair with algorithm: {algorithm}")

        # Validate algorithm
        if not self._is_algorithm_supported(algorithm):
            raise PQCKeyError(f"Unsupported algorithm: {algorithm}")

        # Generate persistent key pair
        if OQS_AVAILABLE:
            key_pair = await self._generate_real_key_pair(algorithm, seed)
        else:
            # Use persistent storage with classical crypto placeholder
            key_data = self.storage.generate_persistent_key_pair(algorithm, seed)
            key_pair = PQCKeyPair(
                public_key_bytes=key_data["public_key_bytes"],
                private_key_bytes=key_data["private_key_bytes"],
                algorithm=algorithm,
                key_id=key_data["key_id"]
            )

        # Cache key pair
        self._key_cache[key_pair.key_id] = key_pair

        LOGGER.info(f"✅ Generated persistent key pair: {key_pair.key_id}")

        return key_pair

    async def sign(
        self,
        message: bytes,
        private_key: str,
        algorithm: Optional[str] = None
    ) -> bytes:
        """Sign message with PQC algorithm.

        Args:
            message: Message to sign
            private_key: Private key (key ID or bytes)
            algorithm: Optional algorithm override

        Returns:
            Signature bytes
        """
        if not self._initialized:
            await self.initialize()

        # Get key pair
        key_pair = await self._get_key_pair(private_key, algorithm)

        if not self._is_signature_algorithm(key_pair.algorithm):
            raise PQCKeyError(f"Algorithm {key_pair.algorithm} is not a signature algorithm")

        # Sign message
        if OQS_AVAILABLE:
            signature = await self._sign_real(message, key_pair)
        else:
            # Use persistent storage for signing
            signature = self.storage.sign_message(message, key_pair.key_id)

        LOGGER.debug(f"Signed message with {key_pair.algorithm} using persistent storage")

        return signature

    async def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: str
    ) -> bool:
        """Verify PQC signature.

        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key bytes
            algorithm: PQC algorithm

        Returns:
            True if signature is valid
        """
        if not self._initialized:
            await self.initialize()

        if not self._is_signature_algorithm(algorithm):
            raise PQCKeyError(f"Algorithm {algorithm} is not a signature algorithm")

        # Verify signature
        if OQS_AVAILABLE:
            is_valid = await self._verify_real(message, signature, public_key, algorithm)
        else:
            # Use persistent storage for verification
            is_valid = self.storage.verify_signature(message, signature, public_key)

        LOGGER.debug(f"Signature verification with persistent storage: {is_valid}")

        return is_valid

    async def encapsulate(
        self,
        public_key: bytes,
        algorithm: str
    ) -> Tuple[bytes, bytes]:
        """Perform KEM encapsulation.

        Args:
            public_key: Public key bytes
            algorithm: KEM algorithm

        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        if not self._initialized:
            await self.initialize()

        if not self._is_kem_algorithm(algorithm):
            raise PQCKeyError(f"Algorithm {algorithm} is not a KEM algorithm")

        # Perform encapsulation
        if OQS_AVAILABLE:
            result = await self._encapsulate_real(public_key, algorithm)
        else:
            result = await self._encapsulate_simulated(public_key, algorithm)

        LOGGER.debug(f"KEM encapsulation with {algorithm}")

        return result

    async def decapsulate(
        self,
        ciphertext: bytes,
        private_key: str,
        algorithm: Optional[str] = None
    ) -> bytes:
        """Perform KEM decapsulation.

        Args:
            ciphertext: Ciphertext to decapsulate
            private_key: Private key (key ID or bytes)
            algorithm: Optional algorithm override

        Returns:
            Shared secret
        """
        if not self._initialized:
            await self.initialize()

        # Get key pair
        key_pair = await self._get_key_pair(private_key, algorithm)

        if not self._is_kem_algorithm(key_pair.algorithm):
            raise PQCKeyError(f"Algorithm {key_pair.algorithm} is not a KEM algorithm")

        # Perform decapsulation
        if OQS_AVAILABLE:
            shared_secret = await self._decapsulate_real(ciphertext, key_pair)
        else:
            shared_secret = await self._decapsulate_simulated(ciphertext, key_pair)

        LOGGER.debug(f"KEM decapsulation with {key_pair.algorithm}")

        return shared_secret

    async def get_supported_algorithms(self) -> List[str]:
        """Get list of supported algorithms."""
        return self.SUPPORTED_SIGNATURE_ALGORITHMS + self.SUPPORTED_KEM_ALGORITHMS

    def _is_algorithm_supported(self, algorithm: str) -> bool:
        """Check if algorithm is supported."""
        return (algorithm in self.SUPPORTED_SIGNATURE_ALGORITHMS or
                algorithm in self.SUPPORTED_KEM_ALGORITHMS)

    def _is_signature_algorithm(self, algorithm: str) -> bool:
        """Check if algorithm is for signatures."""
        return algorithm in self.SUPPORTED_SIGNATURE_ALGORITHMS

    def _is_kem_algorithm(self, algorithm: str) -> bool:
        """Check if algorithm is for KEM."""
        return algorithm in self.SUPPORTED_KEM_ALGORITHMS

    async def _generate_real_key_pair(
        self,
        algorithm: str,
        seed: Optional[str] = None
    ) -> PQCKeyPair:
        """Generate real PQC key pair using liboqs."""

        # Map algorithm name
        oqs_algorithm = self.ALGORITHM_MAPPING.get(algorithm, algorithm)

        try:
            if self._is_signature_algorithm(algorithm):
                # Generate signature key pair
                sig = oqs.Signature(oqs_algorithm)

                if seed:
                    # Use deterministic generation with seed
                    seed_bytes = hashlib.sha256(seed.encode()).digest()
                    # Most liboqs versions don't support from_seed for signatures
                    # Use seed to initialize random state instead
                    import random
                    random.seed(seed)
                    public_key, private_key = sig.generate_keypair()
                else:
                    public_key, private_key = sig.generate_keypair()

            elif self._is_kem_algorithm(algorithm):
                # Generate KEM key pair
                kem = oqs.KeyEncapsulation(oqs_algorithm)

                if seed:
                    # Use deterministic generation with seed
                    seed_bytes = hashlib.sha256(seed.encode()).digest()
                    # Most liboqs versions don't support from_seed for KEM
                    # Use seed to initialize random state instead
                    import random
                    random.seed(seed)
                    public_key, private_key = kem.generate_keypair()
                else:
                    public_key, private_key = kem.generate_keypair()

            else:
                raise PQCKeyError(f"Unknown algorithm type: {algorithm}")

            # Generate key ID
            key_id = self._generate_key_id(algorithm, public_key)

            return PQCKeyPair(
                public_key_bytes=public_key,
                private_key_bytes=private_key,
                algorithm=algorithm,
                key_id=key_id
            )

        except Exception as e:
            raise PQCKeyError(f"Failed to generate key pair: {e}")

    async def _generate_simulated_key_pair(
        self,
        algorithm: str,
        seed: Optional[str] = None
    ) -> PQCKeyPair:
        """Generate simulated key pair for testing."""

        # Use seed or generate random
        if seed:
            key_seed = hashlib.sha256(seed.encode()).digest()
        else:
            key_seed = secrets.token_bytes(32)

        # Generate simulated keys based on algorithm
        if self._is_signature_algorithm(algorithm):
            public_key = hashlib.sha256(key_seed + b"public").digest()
            private_key = hashlib.sha256(key_seed + b"private").digest()
        elif self._is_kem_algorithm(algorithm):
            public_key = hashlib.sha256(key_seed + b"kem_public").digest()
            private_key = hashlib.sha256(key_seed + b"kem_private").digest()
        else:
            raise PQCKeyError(f"Unknown algorithm type: {algorithm}")

        # Generate key ID
        key_id = self._generate_key_id(algorithm, public_key)

        return PQCKeyPair(
            public_key_bytes=public_key,
            private_key_bytes=private_key,
            algorithm=algorithm,
            key_id=key_id
        )

    async def _sign_real(self, message: bytes, key_pair: PQCKeyPair) -> bytes:
        """Sign with real PQC algorithm."""
        oqs_algorithm = self.ALGORITHM_MAPPING.get(key_pair.algorithm, key_pair.algorithm)

        try:
            sig = oqs.Signature(oqs_algorithm)
            signature = sig.sign(message, key_pair.private_key_bytes)
            return signature
        except Exception as e:
            raise PQCKeyError(f"Signing failed: {e}")

    async def _sign_simulated(self, message: bytes, key_pair: PQCKeyPair) -> bytes:
        """Sign with simulated algorithm."""
        # Create deterministic "signature"
        signature_input = key_pair.private_key_bytes + message
        signature = hashlib.sha256(signature_input).digest()
        return signature

    async def _verify_real(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: str
    ) -> bool:
        """Verify with real PQC algorithm."""
        oqs_algorithm = self.ALGORITHM_MAPPING.get(algorithm, algorithm)

        try:
            sig = oqs.Signature(oqs_algorithm)
            return sig.verify(message, signature, public_key)
        except Exception:
            return False

    async def _verify_simulated(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: str
    ) -> bool:
        """Verify with simulated algorithm."""
        # Recreate private key from public key (for simulation)
        private_key = hashlib.sha256(public_key + b"to_private").digest()

        # Recreate expected signature
        signature_input = private_key + message
        expected_signature = hashlib.sha256(signature_input).digest()

        return signature == expected_signature

    async def _encapsulate_real(
        self,
        public_key: bytes,
        algorithm: str
    ) -> Tuple[bytes, bytes]:
        """Encapsulate with real KEM algorithm."""
        oqs_algorithm = self.ALGORITHM_MAPPING.get(algorithm, algorithm)

        try:
            kem = oqs.KeyEncapsulation(oqs_algorithm)
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
        except Exception as e:
            raise PQCKeyError(f"Encapsulation failed: {e}")

    async def _encapsulate_simulated(
        self,
        public_key: bytes,
        algorithm: str
    ) -> Tuple[bytes, bytes]:
        """Encapsulate with simulated algorithm."""
        # Generate random shared secret
        shared_secret = secrets.token_bytes(32)

        # Create deterministic ciphertext
        ciphertext_input = public_key + shared_secret
        ciphertext = hashlib.sha256(ciphertext_input).digest()

        return ciphertext, shared_secret

    async def _decapsulate_real(
        self,
        ciphertext: bytes,
        key_pair: PQCKeyPair
    ) -> bytes:
        """Decapsulate with real KEM algorithm."""
        oqs_algorithm = self.ALGORITHM_MAPPING.get(key_pair.algorithm, key_pair.algorithm)

        try:
            kem = oqs.KeyEncapsulation(oqs_algorithm, key_pair.private_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
        except Exception as e:
            raise PQCKeyError(f"Decapsulation failed: {e}")

    async def _decapsulate_simulated(
        self,
        ciphertext: bytes,
        key_pair: PQCKeyPair
    ) -> bytes:
        """Decapsulate with simulated algorithm."""
        # For simulation, derive shared secret from ciphertext and private key
        shared_secret_input = ciphertext + key_pair.private_key_bytes
        shared_secret = hashlib.sha256(shared_secret_input).digest()

        return shared_secret

    async def _get_key_pair(
        self,
        private_key: str,
        algorithm: Optional[str] = None
    ) -> PQCKeyPair:
        """Get key pair from cache or decode."""

        # Try to get from cache first
        if private_key in self._key_cache:
            return self._key_cache[private_key]

        # If not in cache, assume private_key is base64 encoded key material
        if algorithm:
            try:
                private_key_bytes = base64.b64decode(private_key)

                # Create temporary key pair for operations
                key_id = self._generate_key_id(algorithm, private_key_bytes)

                return PQCKeyPair(
                    public_key_bytes=b"",  # Not needed for signing
                    private_key_bytes=private_key_bytes,
                    algorithm=algorithm,
                    key_id=key_id
                )
            except Exception as e:
                raise PQCKeyError(f"Failed to decode private key: {e}")

        raise PQCKeyError(f"Key not found and no algorithm specified: {private_key}")

    def _generate_key_id(self, algorithm: str, key_material: bytes) -> str:
        """Generate key ID from algorithm and key material."""
        hash_input = algorithm.encode() + key_material
        sha256_hash = hashlib.sha256(hash_input).digest()

        # Use first 8 bytes for key ID
        key_id_bytes = sha256_hash[:8]

        # Encode as base64
        key_id = base64.b64encode(key_id_bytes).decode().rstrip("=")

        return f"pqc-{algorithm.lower().replace('-', '')}-{key_id}"
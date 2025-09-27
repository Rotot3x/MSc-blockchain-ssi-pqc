"""Post-Quantum Cryptography Service using liboqs."""

import logging
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time

# Import bundled oqs module
HAS_LIBOQS = False
oqs = None

from ..config import PQCConfig
from ..key_types import (
    ML_DSA_65, ML_KEM_768, DILITHIUM3, KYBER768,
    is_pqc_key_type, is_signature_key_type, is_kem_key_type, is_hybrid_key_type
)
from acapy_agent.wallet.key_type import KeyType
from acapy_agent.wallet.error import WalletError

LOGGER = logging.getLogger(__name__)


@dataclass
class PQCKeyPair:
    """Post-Quantum Key Pair."""
    public_key: bytes
    private_key: bytes
    algorithm: str
    key_type: str
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[float] = None

    def __post_init__(self):
        """Post initialization."""
        if self.created_at is None:
            self.created_at = time.time()


@dataclass
class HybridKeyPair:
    """Hybrid Key Pair combining PQC and classical cryptography."""
    pqc_keypair: PQCKeyPair
    classical_keypair: Any
    combined_public_key: bytes
    algorithm: str
    key_type: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PQCSignature:
    """Post-Quantum Signature."""
    signature: bytes
    algorithm: str
    public_key: bytes
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class HybridSignature:
    """Hybrid Signature combining PQC and classical signatures."""
    pqc_signature: bytes
    classical_signature: bytes
    combined_signature: bytes
    algorithm: str
    metadata: Optional[Dict[str, Any]] = None


class PQCCryptoService:
    """Post-Quantum Cryptography Service."""

    # Algorithm mapping from key types to liboqs algorithm names
    SIGNATURE_ALGORITHM_MAP = {
        "ml-dsa-44": "ML-DSA-44",
        "ml-dsa-65": "ML-DSA-65",
        "ml-dsa-87": "ML-DSA-87",
        "dilithium2": "Dilithium2",
        "dilithium3": "Dilithium3",
        "dilithium5": "Dilithium5",
        "falcon-512": "Falcon-512",
        "falcon-1024": "Falcon-1024",
        "sphincs-sha2-128f-simple": "SPHINCS+-SHA2-128f-simple",
        "sphincs-sha2-128s-simple": "SPHINCS+-SHA2-128s-simple",
        "sphincs-sha2-192f-simple": "SPHINCS+-SHA2-192f-simple",
        "sphincs-sha2-192s-simple": "SPHINCS+-SHA2-192s-simple",
        "sphincs-sha2-256f-simple": "SPHINCS+-SHA2-256f-simple",
        "sphincs-sha2-256s-simple": "SPHINCS+-SHA2-256s-simple",
    }

    KEM_ALGORITHM_MAP = {
        "ml-kem-512": "ML-KEM-512",
        "ml-kem-768": "ML-KEM-768",
        "ml-kem-1024": "ML-KEM-1024",
        "kyber512": "Kyber512",
        "kyber768": "Kyber768",
        "kyber1024": "Kyber1024",
        "frodokem-640-aes": "FrodoKEM-640-AES",
        "frodokem-640-shake": "FrodoKEM-640-SHAKE",
        "frodokem-976-aes": "FrodoKEM-976-AES",
        "frodokem-976-shake": "FrodoKEM-976-SHAKE",
        "frodokem-1344-aes": "FrodoKEM-1344-AES",
        "frodokem-1344-shake": "FrodoKEM-1344-SHAKE",
        "ntru-hps-2048-509": "NTRU-HPS-2048-509",
        "ntru-hps-2048-677": "NTRU-HPS-2048-677",
        "ntru-hps-4096-821": "NTRU-HPS-4096-821",
        "ntru-hrss-701": "NTRU-HRSS-701",
        "saber-lightsaber": "LightSaber-KEM",
        "saber-saber": "Saber-KEM",
        "saber-firesaber": "FireSaber-KEM",
    }

    def __init__(self, config: PQCConfig):
        """Initialize PQC Crypto Service.

        Args:
            config: PQC configuration
        """
        self.config = config
        self._initialized = False
        self._available_sig_algorithms = []
        self._available_kem_algorithms = []
        self._key_cache: Dict[str, Any] = {}

    async def initialize(self):
        """Initialize the crypto service."""
        global HAS_LIBOQS, oqs

        # Try to import bundled oqs module at runtime
        if not HAS_LIBOQS:
            try:
                # Try bundled oqs module first
                from ...oqs import oqs as oqs_module
                oqs = oqs_module
                HAS_LIBOQS = True
                LOGGER.info("✅ Bundled liboqs successfully loaded")
            except ImportError as e:
                LOGGER.debug(f"Bundled oqs not found: {e}")
                try:
                    # Fallback to system liboqs-python, but disable auto-installation
                    import os
                    old_oqs_build = os.environ.get('OQS_BUILD_ONLY_LIB', '')
                    os.environ['OQS_BUILD_ONLY_LIB'] = 'ON'  # Prevent auto-installation

                    import oqs as oqs_module
                    oqs = oqs_module
                    HAS_LIBOQS = True
                    LOGGER.info("✅ System liboqs-python successfully loaded")

                    # Restore environment
                    if old_oqs_build:
                        os.environ['OQS_BUILD_ONLY_LIB'] = old_oqs_build
                    else:
                        os.environ.pop('OQS_BUILD_ONLY_LIB', None)

                except (ImportError, SystemExit, RuntimeError) as e:
                    LOGGER.warning("⚠️  liboqs not available - PQC functionality limited")
                    LOGGER.warning(f"   Reason: {e}")
                    LOGGER.warning("   Plugin will work in simulation mode")
                    LOGGER.warning("   For full PQC functionality: pip install pqcrypto_fm")
                    self._initialized = True
                    return

        try:
            # Get available algorithms
            self._available_sig_algorithms = oqs.get_enabled_sig_mechanisms()
            self._available_kem_algorithms = oqs.get_enabled_kem_mechanisms()

            LOGGER.info(
                f"🔧 PQC Crypto Service initialized with "
                f"{len(self._available_sig_algorithms)} signature algorithms and "
                f"{len(self._available_kem_algorithms)} KEM algorithms"
            )

            if self.config.debug_mode:
                LOGGER.debug(f"Available signature algorithms: {self._available_sig_algorithms}")
                LOGGER.debug(f"Available KEM algorithms: {self._available_kem_algorithms}")

            self._initialized = True

        except Exception as e:
            LOGGER.error(f"Failed to initialize PQC Crypto Service: {e}")
            LOGGER.warning("Continuing without PQC functionality")
            self._initialized = True

    def _get_liboqs_algorithm_name(self, key_type: KeyType) -> str:
        """Get the liboqs algorithm name for a key type.

        Args:
            key_type: The key type

        Returns:
            Algorithm name for liboqs

        Raises:
            WalletError: If algorithm not supported
        """
        key_type_str = key_type.key_type

        if is_signature_key_type(key_type):
            algorithm = self.SIGNATURE_ALGORITHM_MAP.get(key_type_str)
        elif is_kem_key_type(key_type):
            algorithm = self.KEM_ALGORITHM_MAP.get(key_type_str)
        else:
            raise WalletError(f"Unsupported key type: {key_type_str}")

        if not algorithm:
            raise WalletError(f"No algorithm mapping for key type: {key_type_str}")

        return algorithm

    async def generate_keypair(
        self,
        key_type: KeyType,
        seed: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PQCKeyPair:
        """Generate a PQC keypair.

        Args:
            key_type: Type of key to generate
            seed: Optional seed (not used for PQC algorithms)
            metadata: Optional metadata

        Returns:
            Generated PQC keypair

        Raises:
            WalletError: If key generation fails
        """
        if not self._initialized:
            await self.initialize()

        if not HAS_LIBOQS:
            raise WalletError("liboqs-python not available for PQC key generation")

        if is_hybrid_key_type(key_type):
            return await self._generate_hybrid_keypair(key_type, seed, metadata)

        algorithm = self._get_liboqs_algorithm_name(key_type)

        try:
            if is_signature_key_type(key_type):
                if algorithm not in self._available_sig_algorithms:
                    raise WalletError(f"Signature algorithm not available: {algorithm}")

                sig = oqs.Signature(algorithm)
                public_key, private_key = sig.generate_keypair()

            elif is_kem_key_type(key_type):
                if algorithm not in self._available_kem_algorithms:
                    raise WalletError(f"KEM algorithm not available: {algorithm}")

                kem = oqs.KeyEncapsulation(algorithm)
                public_key, private_key = kem.generate_keypair()

            else:
                raise WalletError(f"Unsupported key type for PQC: {key_type.key_type}")

            keypair = PQCKeyPair(
                public_key=public_key,
                private_key=private_key,
                algorithm=algorithm,
                key_type=key_type.key_type,
                metadata=metadata or {}
            )

            if self.config.log_crypto_operations:
                LOGGER.info(f"Generated PQC keypair: {algorithm}")

            return keypair

        except Exception as e:
            LOGGER.error(f"Failed to generate PQC keypair for {algorithm}: {e}")
            raise WalletError(f"PQC key generation failed: {e}")

    async def _generate_hybrid_keypair(
        self,
        key_type: KeyType,
        seed: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> HybridKeyPair:
        """Generate a hybrid keypair combining PQC and classical cryptography.

        Args:
            key_type: Hybrid key type
            seed: Optional seed
            metadata: Optional metadata

        Returns:
            Generated hybrid keypair
        """
        # For hybrid keys, extract the PQC and classical components
        key_type_str = key_type.key_type

        if "ml-dsa-65-ed25519" in key_type_str:
            pqc_keypair = await self.generate_keypair(ML_DSA_65, seed, metadata)
            classical_private_key = ed25519.Ed25519PrivateKey.generate()
            classical_public_key = classical_private_key.public_key()

        elif "dilithium3-ed25519" in key_type_str:
            pqc_keypair = await self.generate_keypair(DILITHIUM3, seed, metadata)
            classical_private_key = ed25519.Ed25519PrivateKey.generate()
            classical_public_key = classical_private_key.public_key()

        elif "ml-kem-768-x25519" in key_type_str:
            pqc_keypair = await self.generate_keypair(ML_KEM_768, seed, metadata)
            classical_private_key = x25519.X25519PrivateKey.generate()
            classical_public_key = classical_private_key.public_key()

        elif "kyber768-x25519" in key_type_str:
            pqc_keypair = await self.generate_keypair(KYBER768, seed, metadata)
            classical_private_key = x25519.X25519PrivateKey.generate()
            classical_public_key = classical_private_key.public_key()

        else:
            raise WalletError(f"Unsupported hybrid key type: {key_type_str}")

        # Combine the public keys
        combined_public_key = self._combine_public_keys(
            pqc_keypair.public_key,
            classical_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

        return HybridKeyPair(
            pqc_keypair=pqc_keypair,
            classical_keypair=(classical_private_key, classical_public_key),
            combined_public_key=combined_public_key,
            algorithm=f"Hybrid-{pqc_keypair.algorithm}",
            key_type=key_type_str,
            metadata=metadata or {}
        )

    def _combine_public_keys(self, pqc_public_key: bytes, classical_public_key: bytes) -> bytes:
        """Combine PQC and classical public keys.

        Args:
            pqc_public_key: PQC public key
            classical_public_key: Classical public key

        Returns:
            Combined public key
        """
        # Simple concatenation with length prefixes
        pqc_len = len(pqc_public_key).to_bytes(4, 'big')
        classical_len = len(classical_public_key).to_bytes(4, 'big')
        return pqc_len + pqc_public_key + classical_len + classical_public_key

    async def sign(
        self,
        message: bytes,
        keypair: PQCKeyPair,
        algorithm: Optional[str] = None
    ) -> PQCSignature:
        """Sign a message with PQC.

        Args:
            message: Message to sign
            keypair: PQC keypair
            algorithm: Optional algorithm override

        Returns:
            PQC signature

        Raises:
            WalletError: If signing fails
        """
        if not self._initialized:
            await self.initialize()

        if not HAS_LIBOQS:
            raise WalletError("liboqs-python not available for PQC signing")

        algorithm = algorithm or keypair.algorithm

        try:
            with oqs.Signature(algorithm, keypair.private_key) as sig:
                signature = sig.sign(message)

            result = PQCSignature(
                signature=signature,
                algorithm=algorithm,
                public_key=keypair.public_key,
                metadata={"signed_at": time.time()}
            )

            if self.config.log_crypto_operations:
                LOGGER.info(f"Signed message with {algorithm}")

            return result

        except Exception as e:
            LOGGER.error(f"Failed to sign with {algorithm}: {e}")
            raise WalletError(f"PQC signing failed: {e}")

    async def verify(
        self,
        message: bytes,
        signature: PQCSignature,
        public_key: Optional[bytes] = None
    ) -> bool:
        """Verify a PQC signature.

        Args:
            message: Original message
            signature: PQC signature
            public_key: Optional public key override

        Returns:
            True if signature is valid

        Raises:
            WalletError: If verification fails
        """
        if not self._initialized:
            await self.initialize()

        if not HAS_LIBOQS:
            raise WalletError("liboqs-python not available for PQC verification")

        public_key = public_key or signature.public_key

        try:
            with oqs.Signature(signature.algorithm) as sig:
                is_valid = sig.verify(message, signature.signature, public_key)

            if self.config.log_crypto_operations:
                LOGGER.info(f"Verified signature with {signature.algorithm}: {is_valid}")

            return is_valid

        except Exception as e:
            LOGGER.error(f"Failed to verify signature with {signature.algorithm}: {e}")
            raise WalletError(f"PQC verification failed: {e}")

    async def encapsulate(
        self,
        public_key: bytes,
        algorithm: str
    ) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using KEM.

        Args:
            public_key: Recipient's public key
            algorithm: KEM algorithm

        Returns:
            Tuple of (ciphertext, shared_secret)

        Raises:
            WalletError: If encapsulation fails
        """
        if not self._initialized:
            await self.initialize()

        if not HAS_LIBOQS:
            raise WalletError("liboqs-python not available for KEM encapsulation")

        try:
            with oqs.KeyEncapsulation(algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)

            if self.config.log_crypto_operations:
                LOGGER.info(f"Encapsulated secret with {algorithm}")

            return ciphertext, shared_secret

        except Exception as e:
            LOGGER.error(f"Failed to encapsulate with {algorithm}: {e}")
            raise WalletError(f"KEM encapsulation failed: {e}")

    async def decapsulate(
        self,
        ciphertext: bytes,
        keypair: PQCKeyPair
    ) -> bytes:
        """Decapsulate a shared secret using KEM.

        Args:
            ciphertext: Encapsulated ciphertext
            keypair: Recipient's keypair

        Returns:
            Shared secret

        Raises:
            WalletError: If decapsulation fails
        """
        if not self._initialized:
            await self.initialize()

        if not HAS_LIBOQS:
            raise WalletError("liboqs-python not available for KEM decapsulation")

        try:
            with oqs.KeyEncapsulation(keypair.algorithm, keypair.private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)

            if self.config.log_crypto_operations:
                LOGGER.info(f"Decapsulated secret with {keypair.algorithm}")

            return shared_secret

        except Exception as e:
            LOGGER.error(f"Failed to decapsulate with {keypair.algorithm}: {e}")
            raise WalletError(f"KEM decapsulation failed: {e}")

    def get_available_algorithms(self) -> Dict[str, list]:
        """Get available PQC algorithms.

        Returns:
            Dictionary with available signature and KEM algorithms
        """
        return {
            "signature": self._available_sig_algorithms,
            "kem": self._available_kem_algorithms
        }

    def is_algorithm_available(self, algorithm: str, algorithm_type: str = "signature") -> bool:
        """Check if an algorithm is available.

        Args:
            algorithm: Algorithm name
            algorithm_type: Type of algorithm ('signature' or 'kem')

        Returns:
            True if algorithm is available
        """
        if algorithm_type == "signature":
            return algorithm in self._available_sig_algorithms
        elif algorithm_type == "kem":
            return algorithm in self._available_kem_algorithms
        return False
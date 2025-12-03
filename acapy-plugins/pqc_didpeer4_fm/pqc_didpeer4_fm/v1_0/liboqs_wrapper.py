"""Direct liboqs-python integration for PQC key generation and operations.

This module provides a wrapper around liboqs-python for generating and using
ML-DSA-65 (Dilithium3) and ML-KEM-768 (Kyber768) keys.
"""

import logging
from typing import Tuple, Optional

try:
    import oqs
except ImportError:
    raise ImportError(
        "liboqs-python is required for PQC support. "
        "Install with: pip install liboqs-python>=0.10.0"
    )

LOGGER = logging.getLogger(__name__)


class LibOQSWrapper:
    """Wrapper for liboqs-python providing PQC key generation and operations."""

    def __init__(self):
        """Initialize LibOQS wrapper."""
        self.oqs = oqs
        LOGGER.info("LibOQS wrapper initialized")

    def generate_ml_dsa_65_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-DSA-65 (Dilithium3) keypair.

        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
        """
        try:
            sig = self.oqs.Signature("Dilithium3")
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            LOGGER.debug(
                f"Generated ML-DSA-65 keypair: "
                f"public_key={len(public_key)} bytes, "
                f"secret_key={len(secret_key)} bytes"
            )
            return public_key, secret_key
        except Exception as e:
            LOGGER.error(f"Failed to generate ML-DSA-65 keypair: {e}")
            raise

    def generate_ml_kem_768_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 (Kyber768) keypair.

        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
        """
        try:
            # Use KeyEncapsulation (not KEM) - correct liboqs-python API
            kem = self.oqs.KeyEncapsulation("ML-KEM-768")
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            LOGGER.debug(
                f"Generated ML-KEM-768 keypair: "
                f"public_key={len(public_key)} bytes, "
                f"secret_key={len(secret_key)} bytes"
            )
            return public_key, secret_key
        except Exception as e:
            LOGGER.error(f"Failed to generate ML-KEM-768 keypair: {e}")
            raise

    def sign_ml_dsa_65(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign a message using ML-DSA-65 (Dilithium3).

        Args:
            message: Message to sign
            secret_key: ML-DSA-65 secret key

        Returns:
            bytes: Signature
        """
        try:
            sig = self.oqs.Signature("Dilithium3", secret_key)
            signature = sig.sign(message)
            LOGGER.debug(f"Created ML-DSA-65 signature: {len(signature)} bytes")
            return signature
        except Exception as e:
            LOGGER.error(f"Failed to sign with ML-DSA-65: {e}")
            raise

    def verify_ml_dsa_65(
        self, message: bytes, signature: bytes, public_key: bytes
    ) -> bool:
        """Verify an ML-DSA-65 (Dilithium3) signature.

        Args:
            message: Original message
            signature: Signature to verify
            public_key: ML-DSA-65 public key

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            sig = self.oqs.Signature("Dilithium3")
            is_valid = sig.verify(message, signature, public_key)
            LOGGER.debug(f"ML-DSA-65 signature verification: {is_valid}")
            return is_valid
        except Exception as e:
            LOGGER.error(f"Failed to verify ML-DSA-65 signature: {e}")
            return False

    def encapsulate_ml_kem_768(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using ML-KEM-768 (Kyber768).

        Args:
            public_key: ML-KEM-768 public key

        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
        """
        try:
            kem = self.oqs.KeyEncapsulation("ML-KEM-768")
            ciphertext, shared_secret = kem.encap_secret(public_key)
            LOGGER.debug(
                f"ML-KEM-768 encapsulation: "
                f"ciphertext={len(ciphertext)} bytes, "
                f"shared_secret={len(shared_secret)} bytes"
            )
            return ciphertext, shared_secret
        except Exception as e:
            LOGGER.error(f"Failed to encapsulate with ML-KEM-768: {e}")
            raise

    def decapsulate_ml_kem_768(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret using ML-KEM-768 (Kyber768).

        Args:
            ciphertext: Ciphertext from encapsulation
            secret_key: ML-KEM-768 secret key

        Returns:
            bytes: Shared secret
        """
        try:
            kem = self.oqs.KeyEncapsulation("ML-KEM-768", secret_key)
            shared_secret = kem.decap_secret(ciphertext)
            LOGGER.debug(f"ML-KEM-768 decapsulation: {len(shared_secret)} bytes")
            return shared_secret
        except Exception as e:
            LOGGER.error(f"Failed to decapsulate with ML-KEM-768: {e}")
            raise

    # Convenience aliases for pqc_didcomm_v1.py compatibility
    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Alias for encapsulate_ml_kem_768()."""
        return self.encapsulate_ml_kem_768(public_key)

    def kem_decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Alias for decapsulate_ml_kem_768()."""
        return self.decapsulate_ml_kem_768(ciphertext, secret_key)

    def ml_dsa_sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Alias for sign_ml_dsa_65()."""
        return self.sign_ml_dsa_65(message, secret_key)

    def ml_dsa_verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Alias for verify_ml_dsa_65()."""
        return self.verify_ml_dsa_65(message, signature, public_key)

    @staticmethod
    def get_supported_algorithms() -> dict:
        """Get information about supported PQC algorithms.

        Returns:
            dict: Supported algorithms with their properties
        """
        return {
            "signature": {
                "ml-dsa-65": {
                    "oqs_name": "Dilithium3",
                    "public_key_size": 1952,  # bytes
                    "secret_key_size": 4000,  # bytes
                    "signature_size": 3293,  # bytes
                    "security_level": "NIST Level 3",
                },
            },
            "kem": {
                "ml-kem-768": {
                    "oqs_name": "Kyber768",
                    "public_key_size": 1184,  # bytes
                    "secret_key_size": 2400,  # bytes
                    "ciphertext_size": 1088,  # bytes
                    "shared_secret_size": 32,  # bytes
                    "security_level": "NIST Level 3",
                },
            },
        }


# Global instance
_liboqs_instance: Optional[LibOQSWrapper] = None


def get_liboqs() -> LibOQSWrapper:
    """Get or create the global LibOQS wrapper instance.

    Returns:
        LibOQSWrapper: Global LibOQS wrapper instance
    """
    global _liboqs_instance
    if _liboqs_instance is None:
        _liboqs_instance = LibOQSWrapper()
    return _liboqs_instance

"""PQC Integration into ACA-Py Core Crypto Infrastructure.

This module provides seamless integration of Post-Quantum Cryptography algorithms
into ACA-Py's existing crypto.py module without modifying core files.
"""

import logging
from typing import Tuple, Union, List, Optional

from acapy_agent.wallet.crypto import (
    create_keypair as original_create_keypair,
    sign_message as original_sign_message,
    verify_signed_message as original_verify_signed_message,
)
from acapy_agent.wallet.key_type import KeyType
from acapy_agent.wallet.error import WalletError

from .key_types import (
    PQC_KEY_TYPES, is_pqc_key_type, ML_DSA_44, ML_DSA_65, ML_DSA_87,
    ML_KEM_512, ML_KEM_768, ML_KEM_1024, FALCON_512, FALCON_1024
)
from .services.pqc_crypto_service import PQCCryptoService

LOGGER = logging.getLogger(__name__)


class PQCCryptoIntegration:
    """Integration layer for PQC algorithms into ACA-Py's crypto module."""

    def __init__(self, pqc_crypto_service: PQCCryptoService):
        """Initialize PQC crypto integration.

        Args:
            pqc_crypto_service: PQC crypto service instance
        """
        self.pqc_crypto_service = pqc_crypto_service
        self._original_functions = {}

    async def setup_integration(self):
        """Setup PQC integration into core crypto functions."""
        # Store original functions for fallback
        self._original_functions = {
            'create_keypair': original_create_keypair,
            'sign_message': original_sign_message,
            'verify_signed_message': original_verify_signed_message,
        }

        # Monkey patch crypto functions with PQC-aware versions
        import acapy_agent.wallet.crypto as crypto_module
        crypto_module.create_keypair = self.enhanced_create_keypair
        crypto_module.sign_message = self.enhanced_sign_message
        crypto_module.verify_signed_message = self.enhanced_verify_signed_message

        LOGGER.info("🔒 PQC crypto integration enabled in ACA-Py core")

    def enhanced_create_keypair(
        self, key_type: KeyType, seed: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """Enhanced keypair creation with PQC support.

        Args:
            key_type: The type of key to generate
            seed: Optional seed for keypair generation

        Returns:
            Tuple of (public_key, private_key)

        Raises:
            WalletError: If key type is not supported
        """
        try:
            # Check if it's a PQC key type
            if is_pqc_key_type(key_type):
                LOGGER.debug(f"Creating PQC keypair for {key_type.key_type}")

                # Use PQC crypto service for PQC algorithms
                if key_type in [ML_DSA_44, ML_DSA_65, ML_DSA_87]:
                    keypair = self.pqc_crypto_service.generate_signature_keypair(
                        key_type.key_type, seed
                    )
                    return keypair.public_key, keypair.private_key

                elif key_type in [ML_KEM_512, ML_KEM_768, ML_KEM_1024]:
                    keypair = self.pqc_crypto_service.generate_kem_keypair(
                        key_type.key_type, seed
                    )
                    return keypair.public_key, keypair.private_key

                elif key_type in [FALCON_512, FALCON_1024]:
                    keypair = self.pqc_crypto_service.generate_signature_keypair(
                        key_type.key_type, seed
                    )
                    return keypair.public_key, keypair.private_key

                else:
                    # Generic PQC key generation
                    keypair = self.pqc_crypto_service.generate_signature_keypair(
                        key_type.key_type, seed
                    )
                    return keypair.public_key, keypair.private_key
            else:
                # Fallback to original implementation for non-PQC keys
                return self._original_functions['create_keypair'](key_type, seed)

        except Exception as e:
            LOGGER.error(f"Failed to create keypair for {key_type.key_type}: {e}")
            raise WalletError(f"Keypair creation failed: {e}")

    def enhanced_sign_message(
        self,
        message: Union[List[bytes], bytes],
        secret: bytes,
        key_type: KeyType
    ) -> bytes:
        """Enhanced message signing with PQC support.

        Args:
            message: The message(s) to sign
            secret: The private signing key
            key_type: The key type to derive the signature algorithm from

        Returns:
            The signature bytes

        Raises:
            WalletError: If signing fails
        """
        try:
            # Check if it's a PQC key type
            if is_pqc_key_type(key_type):
                LOGGER.debug(f"Signing with PQC algorithm {key_type.key_type}")

                # Ensure single message for PQC (most PQC algorithms sign single messages)
                messages = message if isinstance(message, list) else [message]
                if len(messages) > 1:
                    raise WalletError(f"PQC algorithm {key_type.key_type} can only sign a single message")

                # Use PQC crypto service for signing
                return self.pqc_crypto_service.sign_message(
                    messages[0], secret, key_type.key_type
                )
            else:
                # Fallback to original implementation for non-PQC keys
                return self._original_functions['sign_message'](message, secret, key_type)

        except Exception as e:
            LOGGER.error(f"Failed to sign message with {key_type.key_type}: {e}")
            raise WalletError(f"Message signing failed: {e}")

    def enhanced_verify_signed_message(
        self,
        message: Union[List[bytes], bytes],
        signature: bytes,
        verkey: bytes,
        key_type: KeyType,
    ) -> bool:
        """Enhanced message verification with PQC support.

        Args:
            message: The message(s) to verify
            signature: The signature to verify
            verkey: The verification key
            key_type: The key type to derive the verification algorithm from

        Returns:
            True if signature is valid, False otherwise

        Raises:
            WalletError: If verification fails
        """
        try:
            # Check if it's a PQC key type
            if is_pqc_key_type(key_type):
                LOGGER.debug(f"Verifying with PQC algorithm {key_type.key_type}")

                # Ensure single message for PQC
                messages = message if isinstance(message, list) else [message]
                if len(messages) > 1:
                    raise WalletError(f"PQC algorithm {key_type.key_type} can only verify a single message")

                # Use PQC crypto service for verification
                return self.pqc_crypto_service.verify_signature(
                    messages[0], signature, verkey, key_type.key_type
                )
            else:
                # Fallback to original implementation for non-PQC keys
                return self._original_functions['verify_signed_message'](
                    message, signature, verkey, key_type
                )

        except Exception as e:
            LOGGER.error(f"Failed to verify signature with {key_type.key_type}: {e}")
            raise WalletError(f"Signature verification failed: {e}")


# Global integration instance
_pqc_integration: Optional[PQCCryptoIntegration] = None


async def setup_pqc_crypto_integration(pqc_crypto_service: PQCCryptoService):
    """Setup global PQC crypto integration.

    Args:
        pqc_crypto_service: PQC crypto service instance
    """
    global _pqc_integration
    _pqc_integration = PQCCryptoIntegration(pqc_crypto_service)
    await _pqc_integration.setup_integration()


def get_pqc_integration() -> Optional[PQCCryptoIntegration]:
    """Get the global PQC integration instance.

    Returns:
        PQC integration instance or None if not setup
    """
    return _pqc_integration
"""PQC Integration into ACA-Py Wallet Infrastructure.

This module provides hooks into the BaseWallet interface to enable PQC operations
through the standard ACA-Py wallet API.
"""

import logging
from typing import Optional, Sequence, Tuple, Union, Any, Dict

from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import KeyType
from acapy_agent.wallet.did_info import DIDInfo, KeyInfo
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.config.injection_context import InjectionContext

from .key_types import is_pqc_key_type, PQC_KEY_TYPES
from .services.pqc_crypto_service import PQCCryptoService
from .services.pqc_wallet_service import PQCWalletService
from .services.pqc_did_service import PQCDidService

LOGGER = logging.getLogger(__name__)


class PQCWalletIntegration:
    """Integration layer for PQC algorithms into ACA-Py's wallet operations."""

    def __init__(
        self,
        pqc_crypto_service: PQCCryptoService,
        pqc_wallet_service: PQCWalletService,
        pqc_did_service: PQCDidService
    ):
        """Initialize PQC wallet integration.

        Args:
            pqc_crypto_service: PQC crypto service
            pqc_wallet_service: PQC wallet service
            pqc_did_service: PQC DID service
        """
        self.pqc_crypto_service = pqc_crypto_service
        self.pqc_wallet_service = pqc_wallet_service
        self.pqc_did_service = pqc_did_service
        self._original_wallet_methods = {}

    async def setup_wallet_integration(self, context: InjectionContext):
        """Setup PQC integration into wallet operations.

        Args:
            context: Injection context
        """
        # Get the wallet instance and enhance it with PQC capabilities
        wallet = context.inject_or(BaseWallet)
        if wallet:
            await self._enhance_wallet_methods(wallet, context)
            LOGGER.info("💼 PQC wallet integration enabled")
        else:
            LOGGER.warning("No wallet instance found for PQC integration")

    async def _enhance_wallet_methods(self, wallet: BaseWallet, context: InjectionContext):
        """Enhance wallet methods with PQC support.

        Args:
            wallet: Wallet instance to enhance
            context: Injection context
        """
        # Store original methods for fallback
        self._original_wallet_methods = {
            'create_signing_key': getattr(wallet, 'create_signing_key', None),
            'create_key': getattr(wallet, 'create_key', None),
            'sign_message': getattr(wallet, 'sign_message', None),
            'verify_message': getattr(wallet, 'verify_message', None),
            'create_local_did': getattr(wallet, 'create_local_did', None),
        }

        # Enhanced wallet methods with PQC support
        async def enhanced_create_signing_key(
            key_type: KeyType,
            seed: Optional[str] = None,
            metadata: Optional[dict] = None
        ) -> KeyInfo:
            """Enhanced create_signing_key with PQC support."""
            if is_pqc_key_type(key_type):
                LOGGER.debug(f"Creating PQC signing key: {key_type.key_type}")
                return await self.pqc_wallet_service.create_pqc_signing_key(
                    context.profile,  # Use profile from context
                    key_type,
                    seed.encode() if seed else None,
                    metadata
                )
            else:
                # Fallback to original method
                original_method = self._original_wallet_methods['create_signing_key']
                if original_method:
                    return await original_method(key_type, seed, metadata)
                else:
                    raise WalletError("Original create_signing_key method not available")

        async def enhanced_create_key(
            key_type: KeyType,
            seed: Optional[str] = None,
            metadata: Optional[dict] = None
        ) -> KeyInfo:
            """Enhanced create_key with PQC support."""
            if is_pqc_key_type(key_type):
                LOGGER.debug(f"Creating PQC key: {key_type.key_type}")
                return await self.pqc_wallet_service.create_pqc_key(
                    context.profile,
                    key_type,
                    seed.encode() if seed else None,
                    metadata
                )
            else:
                # Fallback to original method
                original_method = self._original_wallet_methods['create_key']
                if original_method:
                    return await original_method(key_type, seed, metadata)
                else:
                    raise WalletError("Original create_key method not available")

        async def enhanced_sign_message(
            message: Union[str, bytes],
            from_verkey: str,
            algorithm: Optional[str] = None
        ) -> bytes:
            """Enhanced sign_message with PQC support."""
            try:
                # Try to determine if this is a PQC key by checking the verkey
                # This is a heuristic based on key length and format
                if self._is_pqc_verkey(from_verkey):
                    LOGGER.debug(f"Signing with PQC key: {from_verkey[:20]}...")

                    # Get the key info to determine algorithm
                    key_info = await self._get_key_info_by_verkey(from_verkey, context)
                    if key_info and is_pqc_key_type(key_info.key_type):
                        message_bytes = message.encode() if isinstance(message, str) else message
                        # Note: In a full implementation, we'd need access to the private key
                        # For now, this is a placeholder showing the integration pattern
                        LOGGER.warning("PQC signing requires private key access - using standard wallet")

                # Fallback to original method
                original_method = self._original_wallet_methods['sign_message']
                if original_method:
                    return await original_method(message, from_verkey, algorithm)
                else:
                    raise WalletError("Original sign_message method not available")

            except Exception as e:
                LOGGER.error(f"Enhanced sign_message failed: {e}")
                # Fallback to original method
                original_method = self._original_wallet_methods['sign_message']
                if original_method:
                    return await original_method(message, from_verkey, algorithm)
                else:
                    raise

        async def enhanced_verify_message(
            message: Union[str, bytes],
            signature: bytes,
            from_verkey: str,
            algorithm: Optional[str] = None
        ) -> bool:
            """Enhanced verify_message with PQC support."""
            try:
                # Try to determine if this is a PQC key
                if self._is_pqc_verkey(from_verkey):
                    LOGGER.debug(f"Verifying with PQC key: {from_verkey[:20]}...")

                    # Get the key info to determine algorithm
                    key_info = await self._get_key_info_by_verkey(from_verkey, context)
                    if key_info and is_pqc_key_type(key_info.key_type):
                        message_bytes = message.encode() if isinstance(message, str) else message
                        return self.pqc_crypto_service.verify_signature(
                            message_bytes,
                            signature,
                            from_verkey.encode(),  # Convert verkey to bytes
                            key_info.key_type.key_type
                        )

                # Fallback to original method
                original_method = self._original_wallet_methods['verify_message']
                if original_method:
                    return await original_method(message, signature, from_verkey, algorithm)
                else:
                    raise WalletError("Original verify_message method not available")

            except Exception as e:
                LOGGER.error(f"Enhanced verify_message failed: {e}")
                # Fallback to original method
                original_method = self._original_wallet_methods['verify_message']
                if original_method:
                    return await original_method(message, signature, from_verkey, algorithm)
                else:
                    raise

        async def enhanced_create_local_did(
            method: Optional[str] = None,
            key_type: Optional[KeyType] = None,
            seed: Optional[str] = None,
            did: Optional[str] = None,
            metadata: Optional[dict] = None
        ) -> DIDInfo:
            """Enhanced create_local_did with PQC support."""
            if key_type and is_pqc_key_type(key_type):
                LOGGER.debug(f"Creating local DID with PQC key: {key_type.key_type}")

                # Use PQC DID service for PQC key types
                if method in ["key", "sov"] or not method:
                    # Default to key method for PQC
                    from acapy_agent.wallet.did_method import KEY
                    return await self.pqc_did_service.create_pqc_did(
                        context.profile,
                        method=KEY,
                        key_type=key_type,
                        seed=seed.encode() if seed else None,
                        metadata=metadata
                    )
                else:
                    LOGGER.warning(f"PQC not supported for method {method}, falling back to original")

            # Fallback to original method
            original_method = self._original_wallet_methods['create_local_did']
            if original_method:
                return await original_method(method, key_type, seed, did, metadata)
            else:
                raise WalletError("Original create_local_did method not available")

        # Monkey patch the wallet methods
        wallet.create_signing_key = enhanced_create_signing_key
        wallet.create_key = enhanced_create_key
        wallet.sign_message = enhanced_sign_message
        wallet.verify_message = enhanced_verify_message
        wallet.create_local_did = enhanced_create_local_did

        LOGGER.info("✅ Enhanced wallet methods with PQC support")

    def _is_pqc_verkey(self, verkey: str) -> bool:
        """Heuristic to determine if a verkey belongs to a PQC algorithm.

        Args:
            verkey: Verification key string

        Returns:
            True if likely a PQC key
        """
        # PQC keys are typically much longer than classical keys
        # Ed25519 keys are 32 bytes (44 chars base64), PQC keys are hundreds/thousands of bytes
        if len(verkey) > 100:  # Arbitrary threshold
            return True

        # Check for PQC-specific prefixes if using multikey format
        pqc_prefixes = ["z6ML", "z6MN", "z6MP", "z6MF", "z6MS", "z6MD", "z6MK"]
        return any(verkey.startswith(prefix) for prefix in pqc_prefixes)

    async def _get_key_info_by_verkey(self, verkey: str, context: InjectionContext) -> Optional[KeyInfo]:
        """Get key info by verification key.

        Args:
            verkey: Verification key
            context: Injection context

        Returns:
            KeyInfo if found, None otherwise
        """
        try:
            # Try to get key info from PQC wallet service
            keys = await self.pqc_wallet_service.list_pqc_keys(context.profile)
            for key_info in keys:
                if key_info.verkey == verkey:
                    return key_info
            return None
        except Exception as e:
            LOGGER.debug(f"Could not get key info for {verkey}: {e}")
            return None


# Global integration instance
_pqc_wallet_integration: Optional[PQCWalletIntegration] = None


async def setup_pqc_wallet_integration(
    context: InjectionContext,
    pqc_crypto_service: PQCCryptoService,
    pqc_wallet_service: PQCWalletService,
    pqc_did_service: PQCDidService
):
    """Setup global PQC wallet integration.

    Args:
        context: Injection context
        pqc_crypto_service: PQC crypto service
        pqc_wallet_service: PQC wallet service
        pqc_did_service: PQC DID service
    """
    global _pqc_wallet_integration
    _pqc_wallet_integration = PQCWalletIntegration(
        pqc_crypto_service, pqc_wallet_service, pqc_did_service
    )
    await _pqc_wallet_integration.setup_wallet_integration(context)


def get_pqc_wallet_integration() -> Optional[PQCWalletIntegration]:
    """Get the global PQC wallet integration instance.

    Returns:
        PQC wallet integration instance or None if not setup
    """
    return _pqc_wallet_integration
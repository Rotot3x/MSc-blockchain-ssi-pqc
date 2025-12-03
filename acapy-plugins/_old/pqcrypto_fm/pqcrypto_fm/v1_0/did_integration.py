"""PQC Integration into ACA-Py DID Methods.

This module extends existing DID methods (did:key, did:sov, etc.) with PQC support
without creating new DID methods.
"""

import logging
from typing import Dict, List, Optional

from acapy_agent.wallet.did_method import DIDMethod, DIDMethods
from acapy_agent.wallet.key_type import KeyType, KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager
from acapy_agent.config.injection_context import InjectionContext

from .key_types import (
    PQC_KEY_TYPES, ML_DSA_44, ML_DSA_65, ML_DSA_87,
    ML_KEM_512, ML_KEM_768, ML_KEM_1024, FALCON_512, FALCON_1024,
    SPHINCS_SHA2_128F_SIMPLE, SPHINCS_SHA2_256S_SIMPLE, DILITHIUM2, DILITHIUM3, DILITHIUM5
)

LOGGER = logging.getLogger(__name__)


class PQCDIDIntegration:
    """Integration layer for PQC algorithms into ACA-Py's DID methods."""

    # PQC Multikey prefixes according to draft specifications
    # https://w3c-ccg.github.io/multicodec/
    PQC_MULTIKEY_MAPPINGS = {
        # ML-DSA (Dilithium-based) algorithms
        ML_DSA_44.key_type: {
            "key_type": ML_DSA_44,
            "multikey_prefix": "z6ML",  # Provisional prefix for ML-DSA-44
            "jws_alg": "ML-DSA-44",
            "did_key_method": True,
            "did_sov_method": True,
        },
        ML_DSA_65.key_type: {
            "key_type": ML_DSA_65,
            "multikey_prefix": "z6MN",  # Provisional prefix for ML-DSA-65
            "jws_alg": "ML-DSA-65",
            "did_key_method": True,
            "did_sov_method": True,
        },
        ML_DSA_87.key_type: {
            "key_type": ML_DSA_87,
            "multikey_prefix": "z6MP",  # Provisional prefix for ML-DSA-87
            "jws_alg": "ML-DSA-87",
            "did_key_method": True,
            "did_sov_method": True,
        },

        # Falcon algorithms
        FALCON_512.key_type: {
            "key_type": FALCON_512,
            "multikey_prefix": "z6MF5",  # Provisional prefix for Falcon-512
            "jws_alg": "Falcon-512",
            "did_key_method": True,
            "did_sov_method": False,  # Indy/Sovrin might not support Falcon initially
        },
        FALCON_1024.key_type: {
            "key_type": FALCON_1024,
            "multikey_prefix": "z6MF10", # Provisional prefix for Falcon-1024
            "jws_alg": "Falcon-1024",
            "did_key_method": True,
            "did_sov_method": False,
        },

        # SPHINCS+ algorithms (subset)
        SPHINCS_SHA2_128F_SIMPLE.key_type: {
            "key_type": SPHINCS_SHA2_128F_SIMPLE,
            "multikey_prefix": "z6MS128", # Provisional prefix for SPHINCS+-SHA2-128f
            "jws_alg": "SPHINCS+-SHA2-128f-simple",
            "did_key_method": True,
            "did_sov_method": False,
        },
        SPHINCS_SHA2_256S_SIMPLE.key_type: {
            "key_type": SPHINCS_SHA2_256S_SIMPLE,
            "multikey_prefix": "z6MS256", # Provisional prefix for SPHINCS+-SHA2-256s
            "jws_alg": "SPHINCS+-SHA2-256s-simple",
            "did_key_method": True,
            "did_sov_method": False,
        },

        # Legacy Dilithium for backward compatibility
        DILITHIUM2.key_type: {
            "key_type": DILITHIUM2,
            "multikey_prefix": "z6MD2",  # Provisional prefix for Dilithium2
            "jws_alg": "Dilithium2",
            "did_key_method": True,
            "did_sov_method": False,
        },
        DILITHIUM3.key_type: {
            "key_type": DILITHIUM3,
            "multikey_prefix": "z6MD3",  # Provisional prefix for Dilithium3
            "jws_alg": "Dilithium3",
            "did_key_method": True,
            "did_sov_method": False,
        },
        DILITHIUM5.key_type: {
            "key_type": DILITHIUM5,
            "multikey_prefix": "z6MD5",  # Provisional prefix for Dilithium5
            "jws_alg": "Dilithium5",
            "did_key_method": True,
            "did_sov_method": False,
        },

        # ML-KEM (Key Encapsulation) - for DIDComm encryption
        ML_KEM_512.key_type: {
            "key_type": ML_KEM_512,
            "multikey_prefix": "z6MK512", # Provisional prefix for ML-KEM-512
            "jws_alg": None,  # KEMs are not used for signing
            "did_key_method": True,
            "did_sov_method": False,
        },
        ML_KEM_768.key_type: {
            "key_type": ML_KEM_768,
            "multikey_prefix": "z6MK768", # Provisional prefix for ML-KEM-768
            "jws_alg": None,
            "did_key_method": True,
            "did_sov_method": False,
        },
        ML_KEM_1024.key_type: {
            "key_type": ML_KEM_1024,
            "multikey_prefix": "z6MK1024", # Provisional prefix for ML-KEM-1024
            "jws_alg": None,
            "did_key_method": True,
            "did_sov_method": False,
        },
    }

    def __init__(self):
        """Initialize PQC DID integration."""
        self._extended_methods: Dict[str, DIDMethod] = {}

    async def setup_did_integration(self, context: InjectionContext):
        """Setup PQC integration into existing DID methods.

        Args:
            context: Injection context for accessing services
        """
        # Register PQC key types
        await self._register_pqc_key_types(context)

        # Extend existing DID methods with PQC support
        await self._extend_did_methods(context)

        # Integrate with multikey manager
        await self._integrate_multikey_manager()

        LOGGER.info("🆔 PQC DID method integration enabled")

    async def _register_pqc_key_types(self, context: InjectionContext):
        """Register PQC key types in the global key type registry.

        Args:
            context: Injection context
        """
        key_types = context.inject_or(KeyTypes)
        if not key_types:
            key_types = KeyTypes()
            context.injector.bind_instance(KeyTypes, key_types)

        for key_type in PQC_KEY_TYPES:
            try:
                key_types.register(key_type)
                LOGGER.debug(f"Registered PQC key type: {key_type.key_type}")
            except Exception as e:
                LOGGER.warning(f"Failed to register key type {key_type.key_type}: {e}")

        LOGGER.info(f"✅ Registered {len(PQC_KEY_TYPES)} PQC key types")

    async def _extend_did_methods(self, context: InjectionContext):
        """Extend existing DID methods with PQC key type support.

        Args:
            context: Injection context
        """
        did_methods = context.inject_or(DIDMethods)
        if not did_methods:
            did_methods = DIDMethods()
            context.injector.bind_instance(DIDMethods, did_methods)

        # Get signature-capable PQC key types for DID methods
        signature_key_types = [
            key_type for key_type in PQC_KEY_TYPES
            if self._is_signature_algorithm(key_type)
        ]

        # Extend did:key method with PQC support
        await self._extend_did_key_method(did_methods, signature_key_types)

        # Extend did:sov method with supported PQC algorithms
        await self._extend_did_sov_method(did_methods, signature_key_types)

        LOGGER.info("✅ Extended existing DID methods with PQC support")

    async def _extend_did_key_method(self, did_methods: DIDMethods, signature_key_types: List[KeyType]):
        """Extend did:key method with PQC key types.

        Args:
            did_methods: DID methods registry
            signature_key_types: PQC signature key types
        """
        try:
            # Get existing did:key method
            existing_key_method = None
            for method in did_methods.methods:
                if method.method_name == "key":
                    existing_key_method = method
                    break

            if existing_key_method:
                # Create extended did:key method with PQC support
                extended_key_types = list(existing_key_method.key_types) + signature_key_types

                extended_key_method = DIDMethod(
                    method_name="key",
                    key_types=extended_key_types,
                    rotation=existing_key_method.rotation,
                    holder_defined_did=existing_key_method.holder_defined_did,
                )

                # Replace existing method
                did_methods.methods = [
                    extended_key_method if m.method_name == "key" else m
                    for m in did_methods.methods
                ]

                self._extended_methods["key"] = extended_key_method
                LOGGER.info(f"🔑 Extended did:key method with {len(signature_key_types)} PQC algorithms")
            else:
                LOGGER.warning("did:key method not found - creating new one")
                # Create new did:key method with PQC support
                new_key_method = DIDMethod(
                    method_name="key",
                    key_types=signature_key_types,
                    rotation=False,
                    holder_defined_did=False,
                )
                did_methods.register(new_key_method)
                self._extended_methods["key"] = new_key_method

        except Exception as e:
            LOGGER.error(f"Failed to extend did:key method: {e}")

    async def _extend_did_sov_method(self, did_methods: DIDMethods, signature_key_types: List[KeyType]):
        """Extend did:sov method with supported PQC algorithms.

        Args:
            did_methods: DID methods registry
            signature_key_types: PQC signature key types
        """
        try:
            # Get existing did:sov method
            existing_sov_method = None
            for method in did_methods.methods:
                if method.method_name == "sov":
                    existing_sov_method = method
                    break

            if existing_sov_method:
                # Filter PQC algorithms that are compatible with Sovrin/Indy
                sov_compatible_types = [
                    key_type for key_type in signature_key_types
                    if self.PQC_MULTIKEY_MAPPINGS.get(key_type.key_type, {}).get("did_sov_method", False)
                ]

                if sov_compatible_types:
                    # Create extended did:sov method
                    extended_key_types = list(existing_sov_method.key_types) + sov_compatible_types

                    extended_sov_method = DIDMethod(
                        method_name="sov",
                        key_types=extended_key_types,
                        rotation=existing_sov_method.rotation,
                        holder_defined_did=existing_sov_method.holder_defined_did,
                    )

                    # Replace existing method
                    did_methods.methods = [
                        extended_sov_method if m.method_name == "sov" else m
                        for m in did_methods.methods
                    ]

                    self._extended_methods["sov"] = extended_sov_method
                    LOGGER.info(f"🏛️ Extended did:sov method with {len(sov_compatible_types)} PQC algorithms")
                else:
                    LOGGER.info("No Sovrin-compatible PQC algorithms found")
            else:
                LOGGER.warning("did:sov method not found")

        except Exception as e:
            LOGGER.error(f"Failed to extend did:sov method: {e}")

    async def _integrate_multikey_manager(self):
        """Integrate PQC algorithms with multikey manager.

        This adds PQC multikey prefixes to the global ALG_MAPPINGS.
        """
        try:
            # Import multikey manager and extend ALG_MAPPINGS
            from acapy_agent.wallet.keys.manager import ALG_MAPPINGS

            # Add PQC algorithms to ALG_MAPPINGS
            for alg_name, mapping in self.PQC_MULTIKEY_MAPPINGS.items():
                if mapping["jws_alg"]:  # Only add algorithms that support JWS
                    ALG_MAPPINGS[alg_name.lower().replace('-', '')] = {
                        "key_type": mapping["key_type"],
                        "multikey_prefix": mapping["multikey_prefix"],
                        "jws_alg": mapping["jws_alg"],
                    }

            LOGGER.info(f"🔐 Integrated {len(self.PQC_MULTIKEY_MAPPINGS)} PQC algorithms with multikey manager")

        except Exception as e:
            LOGGER.error(f"Failed to integrate with multikey manager: {e}")

    def _is_signature_algorithm(self, key_type: KeyType) -> bool:
        """Check if a key type is a signature algorithm (not KEM).

        Args:
            key_type: Key type to check

        Returns:
            True if it's a signature algorithm
        """
        # KEM algorithms are used for encryption, not signing
        kem_algorithms = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        return key_type not in kem_algorithms

    def get_extended_methods(self) -> Dict[str, DIDMethod]:
        """Get the extended DID methods.

        Returns:
            Dictionary of extended DID methods
        """
        return self._extended_methods.copy()

    def get_pqc_multikey_prefix(self, algorithm: str) -> Optional[str]:
        """Get multikey prefix for a PQC algorithm.

        Args:
            algorithm: PQC algorithm name

        Returns:
            Multikey prefix or None if not found
        """
        mapping = self.PQC_MULTIKEY_MAPPINGS.get(algorithm)
        return mapping["multikey_prefix"] if mapping else None


# Global integration instance
_pqc_did_integration: Optional[PQCDIDIntegration] = None


async def setup_pqc_did_integration(context: InjectionContext):
    """Setup global PQC DID integration.

    Args:
        context: Injection context
    """
    global _pqc_did_integration
    _pqc_did_integration = PQCDIDIntegration()
    await _pqc_did_integration.setup_did_integration(context)


def get_pqc_did_integration() -> Optional[PQCDIDIntegration]:
    """Get the global PQC DID integration instance.

    Returns:
        PQC DID integration instance or None if not setup
    """
    return _pqc_did_integration
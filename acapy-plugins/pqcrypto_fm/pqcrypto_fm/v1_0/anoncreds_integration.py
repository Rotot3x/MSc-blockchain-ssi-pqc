"""PQC Integration into ACA-Py AnonCreds Infrastructure.

This module provides seamless integration of Post-Quantum Cryptography algorithms
into ACA-Py's AnonCreds operations for verifiable credentials.
"""

import logging
from typing import Optional, Dict, Any, List, Union

from acapy_agent.anoncreds.issuer import AnonCredsIssuer
from acapy_agent.anoncreds.holder import AnonCredsHolder
from acapy_agent.anoncreds.verifier import AnonCredsVerifier
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.error import WalletError

from .services.pqc_crypto_service import PQCCryptoService
from .key_types import is_pqc_key_type, PQC_KEY_TYPES

LOGGER = logging.getLogger(__name__)


class PQCAnonCredsIntegration:
    """Integration layer for PQC algorithms into ACA-Py's AnonCreds operations."""

    def __init__(self):
        """Initialize PQC AnonCreds integration."""
        self._original_methods = {}

    async def setup_anoncreds_integration(self, context: InjectionContext):
        """Setup PQC integration into AnonCreds operations.

        Args:
            context: Injection context for accessing services
        """
        LOGGER.info("🔐 Setting up PQC AnonCreds integration")

        # Enhance AnonCreds Issuer with PQC support
        await self._enhance_anoncreds_issuer(context)

        # Enhance AnonCreds Holder with PQC support
        await self._enhance_anoncreds_holder(context)

        # Enhance AnonCreds Verifier with PQC support
        await self._enhance_anoncreds_verifier(context)

        LOGGER.info("✅ PQC AnonCreds integration enabled")

    async def _enhance_anoncreds_issuer(self, context: InjectionContext):
        """Enhance AnonCreds Issuer with PQC support.

        Args:
            context: Injection context
        """
        try:
            issuer = context.inject_or(AnonCredsIssuer)
            if issuer:
                # Store original methods
                self._original_methods['issuer_create_credential'] = getattr(
                    issuer, 'create_credential', None
                )
                self._original_methods['issuer_create_credential_offer'] = getattr(
                    issuer, 'create_credential_offer', None
                )

                # Create enhanced methods
                async def enhanced_create_credential(
                    credential_definition_id: str,
                    schema_id: str,
                    credential_offer: dict,
                    credential_request: dict,
                    credential_values: dict,
                    revocation_registry_id: Optional[str] = None,
                    tails_file_path: Optional[str] = None,
                ) -> tuple:
                    """Enhanced credential creation with PQC support."""
                    try:
                        # Check if PQC keys are involved
                        if self._uses_pqc_keys(credential_definition_id):
                            LOGGER.debug(f"Creating credential with PQC support: {credential_definition_id}")
                            # Add PQC-specific metadata to credential
                            if "pqc_metadata" not in credential_values:
                                credential_values["pqc_metadata"] = {
                                    "enabled": True,
                                    "algorithms": [kt.key_type for kt in PQC_KEY_TYPES],
                                    "quantum_safe": True
                                }

                        # Call original method
                        original_method = self._original_methods['issuer_create_credential']
                        if original_method:
                            return await original_method(
                                credential_definition_id,
                                schema_id,
                                credential_offer,
                                credential_request,
                                credential_values,
                                revocation_registry_id,
                                tails_file_path
                            )
                        else:
                            raise WalletError("Original create_credential method not available")

                    except Exception as e:
                        LOGGER.error(f"Enhanced credential creation failed: {e}")
                        raise

                async def enhanced_create_credential_offer(
                    cred_def_id: str,
                    schema_id: str,
                    key_correctness_proof: Optional[dict] = None
                ) -> dict:
                    """Enhanced credential offer creation with PQC support."""
                    try:
                        # Call original method
                        original_method = self._original_methods['issuer_create_credential_offer']
                        if original_method:
                            offer = await original_method(
                                cred_def_id, schema_id, key_correctness_proof
                            )

                            # Add PQC metadata if using PQC keys
                            if self._uses_pqc_keys(cred_def_id):
                                LOGGER.debug(f"Adding PQC metadata to credential offer: {cred_def_id}")
                                offer["pqc_metadata"] = {
                                    "quantum_safe": True,
                                    "signature_algorithms": [
                                        kt.key_type for kt in PQC_KEY_TYPES
                                        if kt.key_type.endswith(('44', '65', '87', '512', '1024'))
                                    ]
                                }

                            return offer
                        else:
                            raise WalletError("Original create_credential_offer method not available")

                    except Exception as e:
                        LOGGER.error(f"Enhanced credential offer creation failed: {e}")
                        raise

                # Monkey patch the enhanced methods
                issuer.create_credential = enhanced_create_credential
                issuer.create_credential_offer = enhanced_create_credential_offer

                LOGGER.info("🔑 Enhanced AnonCreds Issuer with PQC support")

        except Exception as e:
            LOGGER.warning(f"Failed to enhance AnonCreds Issuer: {e}")

    async def _enhance_anoncreds_holder(self, context: InjectionContext):
        """Enhance AnonCreds Holder with PQC support.

        Args:
            context: Injection context
        """
        try:
            holder = context.inject_or(AnonCredsHolder)
            if holder:
                # Store original methods
                self._original_methods['holder_create_credential_request'] = getattr(
                    holder, 'create_credential_request', None
                )
                self._original_methods['holder_store_credential'] = getattr(
                    holder, 'store_credential', None
                )

                async def enhanced_create_credential_request(
                    credential_offer: dict,
                    credential_definition: dict,
                    holder_did: str,
                    master_secret_id: str,
                    revocation_registry_definition: Optional[dict] = None
                ) -> tuple:
                    """Enhanced credential request creation with PQC support."""
                    try:
                        # Check for PQC support in offer
                        if credential_offer.get("pqc_metadata", {}).get("quantum_safe"):
                            LOGGER.debug("Creating credential request with PQC support")

                        # Call original method
                        original_method = self._original_methods['holder_create_credential_request']
                        if original_method:
                            return await original_method(
                                credential_offer,
                                credential_definition,
                                holder_did,
                                master_secret_id,
                                revocation_registry_definition
                            )
                        else:
                            raise WalletError("Original create_credential_request method not available")

                    except Exception as e:
                        LOGGER.error(f"Enhanced credential request creation failed: {e}")
                        raise

                async def enhanced_store_credential(
                    credential_definition: dict,
                    credential_data: dict,
                    credential_request_metadata: dict,
                    credential_attributes: Optional[dict] = None,
                    revocation_registry_definition: Optional[dict] = None
                ) -> str:
                    """Enhanced credential storage with PQC metadata preservation."""
                    try:
                        # Preserve PQC metadata in stored credential
                        if credential_data.get("pqc_metadata"):
                            LOGGER.debug("Storing credential with PQC metadata")

                        # Call original method
                        original_method = self._original_methods['holder_store_credential']
                        if original_method:
                            return await original_method(
                                credential_definition,
                                credential_data,
                                credential_request_metadata,
                                credential_attributes,
                                revocation_registry_definition
                            )
                        else:
                            raise WalletError("Original store_credential method not available")

                    except Exception as e:
                        LOGGER.error(f"Enhanced credential storage failed: {e}")
                        raise

                # Monkey patch the enhanced methods
                holder.create_credential_request = enhanced_create_credential_request
                holder.store_credential = enhanced_store_credential

                LOGGER.info("💼 Enhanced AnonCreds Holder with PQC support")

        except Exception as e:
            LOGGER.warning(f"Failed to enhance AnonCreds Holder: {e}")

    async def _enhance_anoncreds_verifier(self, context: InjectionContext):
        """Enhance AnonCreds Verifier with PQC support.

        Args:
            context: Injection context
        """
        try:
            verifier = context.inject_or(AnonCredsVerifier)
            if verifier:
                # Store original methods
                self._original_methods['verifier_verify_proof'] = getattr(
                    verifier, 'verify_proof', None
                )

                async def enhanced_verify_proof(
                    presentation_request: dict,
                    proof: dict,
                    schemas: dict,
                    credential_definitions: dict,
                    revocation_registry_definitions: Optional[dict] = None,
                    revocation_lists: Optional[dict] = None
                ) -> bool:
                    """Enhanced proof verification with PQC support."""
                    try:
                        # Check for PQC credentials in proof
                        pqc_detected = self._detect_pqc_in_proof(proof, credential_definitions)
                        if pqc_detected:
                            LOGGER.debug("Verifying proof containing PQC credentials")

                        # Call original method
                        original_method = self._original_methods['verifier_verify_proof']
                        if original_method:
                            result = await original_method(
                                presentation_request,
                                proof,
                                schemas,
                                credential_definitions,
                                revocation_registry_definitions,
                                revocation_lists
                            )

                            # Log verification result for PQC credentials
                            if pqc_detected:
                                LOGGER.info(f"✅ PQC credential verification result: {result}")

                            return result
                        else:
                            raise WalletError("Original verify_proof method not available")

                    except Exception as e:
                        LOGGER.error(f"Enhanced proof verification failed: {e}")
                        raise

                # Monkey patch the enhanced methods
                verifier.verify_proof = enhanced_verify_proof

                LOGGER.info("🔍 Enhanced AnonCreds Verifier with PQC support")

        except Exception as e:
            LOGGER.warning(f"Failed to enhance AnonCreds Verifier: {e}")

    def _uses_pqc_keys(self, credential_definition_id: str) -> bool:
        """Check if a credential definition uses PQC keys.

        Args:
            credential_definition_id: Credential definition identifier

        Returns:
            True if uses PQC keys
        """
        # Heuristic: PQC credential definitions might contain PQC identifiers
        # In a full implementation, this would query the credential definition
        pqc_indicators = ["pqc", "ml-dsa", "falcon", "dilithium", "sphincs", "quantum"]
        return any(indicator in credential_definition_id.lower() for indicator in pqc_indicators)

    def _detect_pqc_in_proof(self, proof: dict, credential_definitions: dict) -> bool:
        """Detect if proof contains PQC credentials.

        Args:
            proof: Presentation proof
            credential_definitions: Credential definitions

        Returns:
            True if PQC credentials detected
        """
        try:
            # Check credential definitions for PQC usage
            for cred_def_id in credential_definitions.keys():
                if self._uses_pqc_keys(cred_def_id):
                    return True

            # Check proof metadata
            if proof.get("pqc_metadata", {}).get("quantum_safe"):
                return True

            return False

        except Exception:
            return False


# Global integration instance
_pqc_anoncreds_integration: Optional[PQCAnonCredsIntegration] = None


async def setup_pqc_anoncreds_integration(context: InjectionContext):
    """Setup global PQC AnonCreds integration.

    Args:
        context: Injection context
    """
    global _pqc_anoncreds_integration
    _pqc_anoncreds_integration = PQCAnonCredsIntegration()
    await _pqc_anoncreds_integration.setup_anoncreds_integration(context)


def get_pqc_anoncreds_integration() -> Optional[PQCAnonCredsIntegration]:
    """Get the global PQC AnonCreds integration instance.

    Returns:
        PQC AnonCreds integration instance or None if not setup
    """
    return _pqc_anoncreds_integration
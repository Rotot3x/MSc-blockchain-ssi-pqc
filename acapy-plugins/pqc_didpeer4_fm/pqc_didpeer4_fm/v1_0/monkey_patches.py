"""Monkey patches for transparent PQC integration.

This module patches BaseConnectionManager and DIDExchangeManager to transparently
replace ED25519/X25519 with ML-DSA-65/ML-KEM-768 when creating did:peer:4 DIDs.

NO API changes needed - existing workflows continue to work!
"""

import logging
from typing import Optional, Sequence, List, Tuple

from acapy_agent.connections.base_manager import BaseConnectionManager
from acapy_agent.protocols.didexchange.v1_0.manager import DIDXManager
from acapy_agent.protocols.didexchange.v1_0.messages.request import DIDXRequest
from acapy_agent.protocols.didexchange.v1_0.messages.response import DIDXResponse
from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.messaging.decorators.attach_decorator import AttachDecorator
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_method import PEER4
from acapy_agent.protocols.coordinate_mediation.v1_0.models.mediation_record import MediationRecord

from .key_types import ML_DSA_65, ML_KEM_768
from .base_manager_patch import (
    create_did_peer_4_pqc_complete,
    create_did_peer_4_conditional_pqc,
    _extract_key_material_in_base58_format_pqc,
    long_did_peer_4_to_short_pqc,
    long_did_peer_to_short_pqc,
    record_keys_for_resolvable_did_pqc,
    resolve_inbound_connection_pqc,
    find_connection_pqc,
)

LOGGER = logging.getLogger(__name__)


# Store original methods for potential fallback
_original_create_did_peer_4 = BaseConnectionManager.create_did_peer_4
_original_qualified_did_with_fallback = DIDXManager._qualified_did_with_fallback
_original_extract_key_material = BaseConnectionManager._extract_key_material_in_base58_format
_original_long_did_peer_4_to_short = BaseConnectionManager.long_did_peer_4_to_short
_original_long_did_peer_to_short = BaseConnectionManager.long_did_peer_to_short
_original_record_keys_for_resolvable_did = BaseConnectionManager.record_keys_for_resolvable_did
_original_find_connection = BaseConnectionManager.find_connection


async def _qualified_did_with_fallback_pqc(
    self,
    conn_rec: ConnRecord,
    my_endpoints: Sequence[str],
    mediation_records: List[MediationRecord],
    use_did_method: Optional[str] = None,
    signing_key: Optional[str] = None,
) -> Tuple[str, Optional[AttachDecorator]]:
    """Patched _qualified_did_with_fallback with PQC signature fix.

    CRITICAL FIX: For did:peer:4 with PQC, the `signing_key` parameter is often
    the `invitation_key` from the out-of-band invitation. However, this key is
    NOT the same as the authentication key in the did:peer:4 DID Document!

    For PQC did:peer:4:
    - The DID contains ML-DSA-65 authentication keys (1952 bytes)
    - The signature MUST use the authentication key from the DID
    - NOT the invitation_key (which might be a different key or from a different DID)

    This patch:
    1. Calls the original method
    2. If the DID is did:peer:4 and signing_key was provided, replaces it with
       the actual authentication key from the created DID
    3. Re-signs the attachment with the correct key

    This ensures DID Exchange signature verification succeeds!
    """
    from acapy_agent.protocols.didexchange.v1_0.manager import LegacyHandlingFallback, DIDPosture

    # Call the original method to get the DID and potentially signed attachment
    did, attach = await _original_qualified_did_with_fallback(
        self, conn_rec, my_endpoints, mediation_records, use_did_method, signing_key
    )

    # Check if we need to re-sign with the correct key
    if did and did.startswith("did:peer:4") and attach and signing_key:
        # The original method signed with signing_key (invitation_key)
        # But for did:peer:4, we should sign with the DID's authentication key!

        LOGGER.info(f"PQC Fix: Re-signing did:peer:4 attachment with DID authentication key")
        LOGGER.debug(f"  Original signing_key: {signing_key[:20]}...")

        # Get the DID's authentication key
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            my_info = await wallet.get_local_did(conn_rec.my_did)

        LOGGER.debug(f"  DID authentication key (verkey): {my_info.verkey[:20]}...")
        LOGGER.debug(f"  Key type: {my_info.key_type}")

        # Only re-sign if the keys are different
        if my_info.verkey != signing_key:
            LOGGER.info(f"  Keys differ! Re-signing with correct authentication key")

            # Re-sign the attachment with the correct key
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                await attach.data.sign(my_info.verkey, wallet)

            LOGGER.info("  ✅ Attachment re-signed with did:peer:4 authentication key")
        else:
            LOGGER.debug("  Keys match, no re-signing needed")

    return did, attach


def apply_all_patches():
    """Apply all monkey patches for transparent PQC integration.

    This function:
    1. Patches BaseConnectionManager.create_did_peer_4 with PQC version
    2. Patches BaseConnectionManager._extract_key_material_in_base58_format for PQC
    3. Patches BaseConnectionManager.long_did_peer_4_to_short to preserve key_type
    4. Patches BaseConnectionManager.long_did_peer_to_short to handle short-form DIDs
    5. Patches DIDXManager._qualified_did_with_fallback for correct PQC signatures
    6. Patches BaseConnectionManager.record_keys_for_resolvable_did for PQC key storage
    7. Patches BaseConnectionManager.resolve_inbound_connection with DEBUG logging
    8. Patches BaseConnectionManager.find_connection to handle long/short form my_did
    9. Extends PEER4 DID method to support ML-DSA-65 and ML-KEM-768 key types

    Called during plugin setup.
    """

    # 1. Patch BaseConnectionManager.create_did_peer_4 with CRYPTO-AGILE wrapper
    # KRYPTO-AGILITÄT: Conditional wrapper that checks metadata["key_type"]
    # - If "ed25519" → Delegates to _original_create_did_peer_4 (pre-plugin behavior)
    # - Otherwise → Uses ML-DSA-65 + ML-KEM-768 (PQC)
    # This enables mixed environments where ED25519 and PQC can coexist!
    BaseConnectionManager.create_did_peer_4 = create_did_peer_4_conditional_pqc

    # 2. Patch BaseConnectionManager._extract_key_material_in_base58_format
    # CRITICAL: This allows out-of-band invitation creation to work with PQC keys
    # by accepting ml-dsa-65-pub and ml-kem-768-pub multicodecs
    BaseConnectionManager._extract_key_material_in_base58_format = staticmethod(
        _extract_key_material_in_base58_format_pqc
    )

    # 3. Patch BaseConnectionManager.long_did_peer_4_to_short
    # CRITICAL: This preserves PQC key_type when converting long-form to short-form,
    # eliminating ED25519 "ghost DIDs" in connections!
    BaseConnectionManager.long_did_peer_4_to_short = long_did_peer_4_to_short_pqc

    # 4. Patch BaseConnectionManager.long_did_peer_to_short
    # CRITICAL FIX: This prevents double-conversion of short-form DIDs during
    # connection lookup, which was causing "No connection found" errors during
    # credential offer handling!
    BaseConnectionManager.long_did_peer_to_short = long_did_peer_to_short_pqc

    # 5. Patch DIDXManager._qualified_did_with_fallback for correct PQC signatures
    # CRITICAL: This ensures did:peer:4 attachments are signed with the DID's
    # authentication key, not the invitation_key!
    DIDXManager._qualified_did_with_fallback = _qualified_did_with_fallback_pqc

    # 6. Patch BaseConnectionManager.record_keys_for_resolvable_did
    # CRITICAL FIX: Stores BOTH keys (ML-DSA-65 auth + ML-KEM-768 keyAgr) in DID_KEY records
    # This enables find_did_for_key(sender_verkey) to work during message handling!
    # Original only stored recipientKeys (ML-KEM-768), causing connection lookup to fail
    # when searching for sender's authentication key (ML-DSA-65)
    BaseConnectionManager.record_keys_for_resolvable_did = record_keys_for_resolvable_did_pqc

    # 7. Patch BaseConnectionManager.resolve_inbound_connection
    # DEBUG PATCH: Adds extensive logging to diagnose why recipient_did is None
    BaseConnectionManager.resolve_inbound_connection = resolve_inbound_connection_pqc

    # 8. Patch BaseConnectionManager.find_connection
    # CRITICAL FIX for credential offer handling: Handles both long and short forms of my_did
    # This fixes "No connection found" errors during credential issuance when:
    # - Connection stored with my_did = LONG-FORM (during DID Exchange)
    # - Credential offer uses my_did = SHORT-FORM (from wallet.get_local_did_for_verkey)
    BaseConnectionManager.find_connection = find_connection_pqc

    # 9. Extend PEER4 key types for validation (optional but recommended)
    if ML_DSA_65 not in PEER4._supported_key_types:
        PEER4._supported_key_types.extend([ML_DSA_65, ML_KEM_768])

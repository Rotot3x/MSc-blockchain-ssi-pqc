"""Patch for acapy_agent/connections/base_manager.py to use PQC keys.

This patch completely replaces BaseConnectionManager.create_did_peer_4 to use
ML-DSA-65 + ML-KEM-768 instead of ED25519, eliminating the creation of ED25519
"ghost DIDs" in the wallet.

NO modifications to acapy_agent source code needed - all changes are in the plugin!
"""

import logging
from typing import Dict, List, Optional, Sequence

from did_peer_4 import encode
from did_peer_4.input_doc import input_doc_from_keys_and_services, KeySpec as KeySpec_DP4

from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.did_method import PEER4
from acapy_agent.protocols.coordinate_mediation.v1_0.models.mediation_record import MediationRecord
from acapy_agent.did.did_key import DIDKey
from acapy_agent.wallet.util import bytes_to_b58, b64_to_bytes
from acapy_agent.connections.base_manager import BaseConnectionManagerError
from acapy_agent.utils.multiformats import multibase, multicodec

from .key_types import ML_DSA_65, ML_KEM_768
from .pqc_multikey import key_info_to_multikey

LOGGER = logging.getLogger(__name__)


async def create_did_peer_4_pqc_complete(
    self,
    svc_endpoints: Optional[Sequence[str]] = None,
    mediation_records: Optional[List[MediationRecord]] = None,
    metadata: Optional[Dict] = None,
) -> DIDInfo:
    """Create a did:peer:4 DID for a connection using PQC keys.

    This is a COMPLETE replacement for BaseConnectionManager.create_did_peer_4
    that uses ML-DSA-65 + ML-KEM-768 instead of ED25519.

    CRITICAL DIFFERENCE from original:
    - Line 165 in original: `key = await wallet.create_key(ED25519)`
    - This version: Creates ML-DSA-65 (authentication) + ML-KEM-768 (key agreement)

    This eliminates the ED25519 "ghost DIDs" that were previously created!

    Args:
        self: BaseConnectionManager instance
        svc_endpoints: Custom endpoints for the DID Document
        mediation_records: Records for mediation that contain routing keys and endpoint
        metadata: Additional metadata for the DID

    Returns:
        DIDInfo: The new PQC did:peer:4 DID
    """
    # Extract routing keys from mediation (same as original)
    routing_keys: List[str] = []
    if mediation_records:
        for mediation_record in mediation_records:
            (
                mediator_routing_keys,
                endpoint,
            ) = await self._route_manager.routing_info(
                self._profile, mediation_record
            )
            routing_keys = [*routing_keys, *(mediator_routing_keys or [])]
            if endpoint:
                svc_endpoints = [endpoint]

    # Build DIDComm v1 services (same as original)
    services = []
    for index, endpoint in enumerate(svc_endpoints or []):
        services.append(
            {
                "id": f"#didcomm-{index}",
                "type": "did-communication",
                "recipientKeys": ["#key-1"],  # ML-KEM-768 key for encryption (key_specs[1] → #key-1)
                "routingKeys": routing_keys,
                "serviceEndpoint": endpoint,
                "priority": index,
            }
        )

    async with self._profile.session() as session:
        wallet = session.inject(BaseWallet)

        # ============================================================
        # PQC MODIFICATION: Create TWO keys instead of one ED25519 key
        # ============================================================

        # 1. Create ML-DSA-65 key for authentication/assertion (signatures)
        sig_key = await wallet.create_key(ML_DSA_65)
        sig_multikey = key_info_to_multikey(sig_key)

        # 2. Create ML-KEM-768 key for key agreement (encryption)
        kem_key = await wallet.create_key(ML_KEM_768)
        kem_multikey = key_info_to_multikey(kem_key)

        LOGGER.info(f"Created PQC keys for did:peer:4:")
        LOGGER.info(f"  - ML-DSA-65 (auth): {sig_multikey[:40]}...")
        LOGGER.info(f"  - ML-KEM-768 (keyAgr): {kem_multikey[:40]}...")

        # 3. Create KeySpec objects for did:peer:4 (same as pqc_peer4_creator.py)
        # NOTE: Order matters! did-peer-4 numbers from 0: key_specs[0] → #key-0, key_specs[1] → #key-1
        key_specs = [
            KeySpec_DP4(
                multikey=sig_multikey,
                relationships=["authentication", "assertionMethod"],  # → #key-0
            ),
            KeySpec_DP4(
                multikey=kem_multikey,
                relationships=["keyAgreement"],  # → #key-1 (used in recipientKeys!)
            ),
        ]

        # 4. Generate did:peer:4 long form (same structure as original)
        input_doc = input_doc_from_keys_and_services(
            keys=key_specs,
            services=services
        )
        did = encode(input_doc)

        LOGGER.info(f"Generated PQC did:peer:4: {did[:80]}...")

        # 5. Create metadata with PQC markers
        did_metadata = metadata if metadata else {}
        did_metadata.update({
            "pqc_enabled": True,
            "signature_algorithm": "ml-dsa-65",
            "key_agreement_algorithm": "ml-kem-768",
            "kem_key_kid": f"{did}#key-1",  # KEM key is key_specs[1] → #key-1
            "kem_verkey": kem_key.verkey,  # CRITICAL: Store KEM verkey for connection lookup!
            "plugin": "pqc_didpeer4_fm",
            "version": "0.1.0",
        })

        LOGGER.error(f"🔑 STORING PQC DID WITH KEM_VERKEY IN METADATA:")
        LOGGER.error(f"   DID: {did[:60]}...")
        LOGGER.error(f"   Primary verkey (ML-DSA-65): {sig_key.verkey[:30]}...")
        LOGGER.error(f"   KEM verkey (ML-KEM-768): {kem_key.verkey[:30]}...")
        LOGGER.error(f"   Metadata keys: {list(did_metadata.keys())}")

        # 6. Create DIDInfo with ML-DSA-65 as primary key type
        did_info = DIDInfo(
            did=did,
            method=PEER4,
            verkey=sig_key.verkey,  # ML-DSA-65 verkey
            metadata=did_metadata,
            key_type=ML_DSA_65,  # NOT ED25519!
        )

        # 7. Store DID in wallet
        await wallet.store_did(did_info)

        # 8. Assign Key IDs - did-peer-4 numbers from 0!
        await wallet.assign_kid_to_key(sig_key.verkey, f"{did}#key-0")  # key_specs[0] → #key-0
        await wallet.assign_kid_to_key(kem_key.verkey, f"{did}#key-1")  # key_specs[1] → #key-1

        LOGGER.info(f"✅ Stored PQC did:peer:4 in wallet with key IDs assigned")

    return did_info


async def create_did_peer_4_conditional_pqc(
    self,
    svc_endpoints: Optional[Sequence[str]] = None,
    mediation_records: Optional[List[MediationRecord]] = None,
    metadata: Optional[Dict] = None,
) -> DIDInfo:
    """Conditional wrapper: Use PQC or original ED25519 based on metadata.
    """
    from acapy_agent.connections.base_manager import BaseConnectionManager

    # Check: Wurde ED25519 explizit gewünscht?
    if metadata and metadata.get("key_type") == "ed25519":
        LOGGER.info("🔓 Kryptoagilität: ED25519 gewünscht → Nutze Original-ACA-Py (KEIN Plugin-Patch)")
        # Delegation an ursprüngliche ACA-Py-Implementierung ohne Plugin-Eingriff
        # Die Original-Funktion wurde gesichert bevor das Plugin sie überschrieben hat
        from . import monkey_patches
        if hasattr(monkey_patches, '_original_create_did_peer_4'):
            return await monkey_patches._original_create_did_peer_4(
                self, svc_endpoints, mediation_records, metadata
            )
        else:
            # Fallback: Rufe die aktuelle Implementierung auf (sollte nicht passieren)
            LOGGER.warning("Original create_did_peer_4 nicht gefunden, nutze aktuelle Implementierung")
            return await BaseConnectionManager.create_did_peer_4(
                self, svc_endpoints, mediation_records, metadata
            )

    # Default: Nutze PQC
    LOGGER.info("🔐 Kryptoagilität: PQC-Algorithmen (ML-DSA-65 + ML-KEM-768)")
    return await create_did_peer_4_pqc_complete(
        self, svc_endpoints, mediation_records, metadata
    )


def _extract_key_material_in_base58_format_pqc(method) -> str:
    """Patched version of BaseConnectionManager._extract_key_material_in_base58_format.

    This patch extends the original method to accept PQC multicodecs (ML-DSA-65 and ML-KEM-768)
    in addition to the classical ED25519 multicodec.

    CRITICAL: This method is called during out-of-band invitation creation when resolving
    recipient keys from did:peer:4 DID Documents. The original only accepts ed25519-pub,
    causing BaseConnectionManagerError when encountering PQC keys.

    This patched version:
    1. Maintains full backward compatibility with all existing key types
    2. Adds support for ml-dsa-65-pub and ml-kem-768-pub multicodecs
    3. Returns base58-encoded key material for all supported key types

    Args:
        method: VerificationMethod from DID Document

    Returns:
        str: Base58-encoded key material

    Raises:
        BaseConnectionManagerError: If key type or multicodec is not supported
    """
    from pydid.verification_method import (
        Ed25519VerificationKey2018,
        Ed25519VerificationKey2020,
        JsonWebKey2020,
        Multikey,
    )

    if isinstance(method, Ed25519VerificationKey2018):
        return method.material
    elif isinstance(method, Ed25519VerificationKey2020):
        raw_data = multibase.decode(method.material)
        if len(raw_data) == 32:  # No multicodec prefix
            return bytes_to_b58(raw_data)
        else:
            codec, key = multicodec.unwrap(raw_data)
            if codec == multicodec.multicodec("ed25519-pub"):
                return bytes_to_b58(key)
            else:
                raise BaseConnectionManagerError(
                    f"Key type {type(method).__name__} "
                    f"with multicodec value {codec} is not supported"
                )

    elif isinstance(method, JsonWebKey2020):
        if method.public_key_jwk.get("kty") == "OKP":
            return bytes_to_b58(b64_to_bytes(method.public_key_jwk.get("x"), True))
        else:
            raise BaseConnectionManagerError(
                f"Key type {type(method).__name__} "
                f"with kty {method.public_key_jwk.get('kty')} is not supported"
            )
    elif isinstance(method, Multikey):
        codec, key = multicodec.unwrap(multibase.decode(method.material))

        # PQC EXTENSION: Accept ML-DSA-65 and ML-KEM-768 in addition to ED25519
        accepted_codecs = [
            multicodec.multicodec("ed25519-pub"),      # Classical
            multicodec.multicodec("ml-dsa-65-pub"),    # PQC signature
            multicodec.multicodec("ml-kem-768-pub"),   # PQC key agreement
        ]

        if codec not in accepted_codecs:
            raise BaseConnectionManagerError(
                f"Expected ed25519-pub, ml-dsa-65-pub, or ml-kem-768-pub multicodec, got: {codec}"
            )

        LOGGER.debug(f"Extracting key material from Multikey with codec: {codec.name}")
        return bytes_to_b58(key)
    else:
        raise BaseConnectionManagerError(
            f"Key type {type(method).__name__} is not supported"
        )


async def long_did_peer_4_to_short_pqc(self, long_dp4: str) -> str:
    """Convert did:peer:4 long format to short format and store in wallet (PQC version).

    This is a patched version of BaseConnectionManager.long_did_peer_4_to_short that:
    1. Preserves the key_type from the original long-form DID (ML-DSA-65 instead of hardcoded ED25519)
    2. Preserves metadata from the original DID
    3. Ensures quantum-safe connections

    CRITICAL DIFFERENCE from original (base_manager.py:112):
    - Original: `key_type=ED25519` (hardcoded)
    - This version: `key_type=long_dp4_info.key_type` (preserved from long-form)

    This eliminates the ED25519 "ghost DIDs" in connections!

    Args:
        self: BaseConnectionManager instance
        long_dp4: Long-form did:peer:4 DID

    Returns:
        str: Short-form did:peer:4 DID
    """
    from did_peer_4 import long_to_short

    async with self._profile.session() as session:
        wallet = session.inject(BaseWallet)
        long_dp4_info = await wallet.get_local_did(long_dp4)

    short_did_peer_4 = long_to_short(long_dp4)

    # CRITICAL: Use key_type from original DID, NOT hardcoded ED25519!
    did_info = DIDInfo(
        did=short_did_peer_4,
        method=PEER4,
        verkey=long_dp4_info.verkey,
        metadata=long_dp4_info.metadata or {},  # Preserve metadata
        key_type=long_dp4_info.key_type,  # Preserve key_type (ML-DSA-65)
    )

    async with self._profile.session() as session:
        wallet = session.inject(BaseWallet)
        await wallet.store_did(did_info)

    LOGGER.info(f"✅ Converted Long-Form to Short-Form (key_type preserved: {long_dp4_info.key_type})")
    LOGGER.debug(f"   Long:  {long_dp4[:80]}...")
    LOGGER.debug(f"   Short: {short_did_peer_4}")

    return did_info.did


async def record_keys_for_resolvable_did_pqc(self, did: str):
    """Store verkeys for lookup against a DID (PQC version that stores BOTH keys).

    This is an EXTENDED version of BaseConnectionManager.record_keys_for_resolvable_did
    that stores BOTH recipient keys (ML-KEM-768) AND authentication keys (ML-DSA-65).

    CRITICAL FIX for connection lookup during message handling:
    - Original (base_manager.py:536-543): Only stores recipientKeys from DIDComm service
    - For classical did:peer:4: recipientKeys = [ED25519] → Stored ✅
    - For PQC did:peer:4: recipientKeys = [ML-KEM-768 (#key-1)] → Stored ✅
      BUT authentication key (ML-DSA-65 #key-0) is NOT stored! ❌

    Problem:
    - DIDComm messages have sender_verkey = sender's authentication key (ML-DSA-65)
    - `find_did_for_key(sender_verkey)` looks up this key in DID_KEY records
    - For PQC: ML-DSA-65 was never stored → NOT FOUND! → Connection lookup fails!

    This patch:
    1. Stores recipientKeys (original behavior - KEM key)
    2. ALSO stores authentication keys (ML-DSA-65 for PQC)
    3. Enables connection lookup for BOTH keys

    Args:
        self: BaseConnectionManager instance
        did: The DID for which to record keys
    """
    from acapy_agent.resolver.did_resolver import DIDResolver

    LOGGER.error(f"[PQC] ====== record_keys_for_resolvable_did_pqc CALLED ======")
    LOGGER.error(f"[PQC]   DID: {did[:80]}...")

    doc, didcomm_services = await self.resolve_didcomm_services(did)

    # 1. Store recipient keys from DIDComm services (original behavior)
    LOGGER.error(f"[PQC]   Found {len(didcomm_services)} DIDComm services")
    for service in didcomm_services:
        recips, _ = await self.verification_methods_for_service(doc, service)
        LOGGER.error(f"[PQC]   Service has {len(recips)} recipient keys")
        for recip in recips:
            recip_key = self._extract_key_material_in_base58_format(recip)
            LOGGER.error(f"[PQC]   Storing RECIPIENT key: {recip_key[:30]}... → DID: {did[:60]}...")
            await self.add_key_for_did(did, recip_key)

    # 2. ALSO store authentication keys (NEW for PQC support!)
    #    This enables find_did_for_key(sender's ML-DSA-65) to work
    if doc.authentication:
        LOGGER.error(f"[PQC]   Found {len(doc.authentication)} authentication keys in DID Document")
        resolver = self._profile.inject(DIDResolver)
        for auth_ref in doc.authentication:
            try:
                auth_method = await resolver.dereference_verification_method(
                    self._profile, auth_ref, document=doc
                )
                auth_key = self._extract_key_material_in_base58_format(auth_method)
                LOGGER.error(f"[PQC]   Storing AUTHENTICATION key: {auth_key[:30]}... → DID: {did[:60]}...")
                await self.add_key_for_did(did, auth_key)
            except Exception as e:
                LOGGER.error(f"[PQC]   ❌ Could not store authentication key: {e}")
                # Don't fail if we can't store auth key (not critical)
                pass
    else:
        LOGGER.error(f"[PQC]   ⚠️  No authentication keys found in DID Document!")

    LOGGER.error(f"[PQC] ====== record_keys_for_resolvable_did_pqc DONE ======")


def long_did_peer_to_short_pqc(self, long_did: str) -> str:
    """Convert did:peer:4 long format to short format and return (PQC-safe version).

    This is a patched version of BaseConnectionManager.long_did_peer_to_short that
    handles BOTH long-form and short-form DIDs correctly.

    CRITICAL FIX for connection lookup during message handling:
    - Original method (base_manager.py:93-97) blindly converts any did:peer:4 to short
    - But after DID Exchange, DIDs are stored in SHORT-FORM in the wallet
    - When `find_connection` (line 877) looks up a connection, it assumes `their_did`
      is LONG-FORM and tries to convert it to short (line 900)
    - If `their_did` is ALREADY short-form, converting it again produces a WRONG hash
    - Connection lookup fails → "No connection found" error in credential offer handler!

    This patch:
    1. Detects if the DID is already in short-form (no multibase-encoded DID Document suffix)
    2. Returns it unchanged if short-form
    3. Converts if long-form (original behavior)

    Short-form vs Long-form detection:
    - Short-form: did:peer:4zQmZMkY... (just the hash, no suffix after 4th ":")
    - Long-form:  did:peer:4zQmZMkY:z25g... (hash + ":" + multibase-encoded doc)
    - Count colons: SHORT has 2 colons ("did:peer:4..."), LONG has 3+ ("did:peer:4...:z...")

    Args:
        self: BaseConnectionManager instance
        long_did: did:peer:4 DID (can be long-form OR short-form)

    Returns:
        str: Short-form did:peer:4 DID
    """
    from did_peer_4 import long_to_short

    # Check if already short-form by counting colons
    # Short-form: "did:peer:4zQm..." → 2 colons
    # Long-form:  "did:peer:4zQm...:z25g..." → 3 colons
    colon_count = long_did.count(":")
    if colon_count == 2:
        LOGGER.debug(f"DID is already short-form (2 colons), returning unchanged: {long_did[:60]}...")
        return long_did

    # Long-form → convert to short
    LOGGER.debug(f"Converting long-form to short-form ({colon_count} colons): {long_did[:60]}...")
    short_did_peer = long_to_short(long_did)
    LOGGER.debug(f"  Result: {short_did_peer}")
    return short_did_peer


async def resolve_inbound_connection_pqc(self, receipt):
    """PQC-aware version of resolve_inbound_connection with sender-based lookup.

    CRITICAL FIX for PQC multi-connection scenario:
    - Problem: wallet.get_local_did_for_verkey(recipient_verkey) can return WRONG DID
      when multiple connections exist (each with different ML-KEM-768 keys)
    - The wallet patch searches ALL DIDs and returns the FIRST match, which might be
      from a DIFFERENT connection (e.g., verifier connection instead of issuer connection)

    Solution: Prefer sender-based connection lookup over recipient-based:
    1. Resolve sender_did from sender_verkey (their authentication key)
    2. Find connection by their_did (sender_did) - this uniquely identifies the connection
    3. Only fall back to recipient_did lookup if sender-based lookup fails

    This matches ED25519 workflow where connections are resolved from sender identity.
    """
    from acapy_agent.core.error import BaseError
    from acapy_agent.storage.error import StorageNotFoundError
    from acapy_agent.wallet.error import WalletNotFoundError

    # InjectionError might be from config.injection_context
    try:
        from acapy_agent.config.injection_context import InjectionError
    except ImportError:
        # Fallback: use BaseError
        InjectionError = BaseError

    LOGGER.error("=" * 80)
    LOGGER.error("[PQC FIX] resolve_inbound_connection CALLED")
    LOGGER.error(f"[PQC FIX]   sender_verkey: {receipt.sender_verkey[:30] if receipt.sender_verkey else 'None'}...")
    LOGGER.error(f"[PQC FIX]   recipient_verkey: {receipt.recipient_verkey[:30] if receipt.recipient_verkey else 'None'}...")

    # Step 1: Resolve sender_did from sender_verkey (CRITICAL for PQC!)
    receipt.sender_did = None
    if receipt.sender_verkey:
        try:
            LOGGER.error(f"[PQC FIX] Looking up sender_did from sender_verkey (their auth key)...")
            receipt.sender_did = await self.find_did_for_key(receipt.sender_verkey)
            LOGGER.error(f"[PQC FIX]   ✅ Found sender_did (their_did): {receipt.sender_did[:60]}...")
        except StorageNotFoundError as e:
            LOGGER.error(f"[PQC FIX]   ⚠️  sender_did NOT found: {e}")
            pass

    # Step 2: Try sender-based connection lookup FIRST (NEW for PQC!)
    if receipt.sender_did:
        LOGGER.error(f"[PQC FIX] TRYING SENDER-BASED LOOKUP (their_did={receipt.sender_did[:60]}...)")
        try:
            connection = await self.find_connection(
                their_did=receipt.sender_did,
                my_did=None,  # Don't filter by my_did yet!
                parent_thread_id=receipt.parent_thread_id,
                auto_complete=True
            )
            if connection:
                LOGGER.error(f"[PQC FIX]   ✅✅✅ Found connection via SENDER lookup!")
                LOGGER.error(f"[PQC FIX]   Connection: {connection.connection_id}")
                LOGGER.error(f"[PQC FIX]   their_did: {connection.their_did}")
                LOGGER.error(f"[PQC FIX]   my_did: {connection.my_did}")

                # Set recipient_did from the connection's my_did (correct one!)
                receipt.recipient_did = connection.my_did
                LOGGER.error(f"[PQC FIX]   Set recipient_did from connection: {receipt.recipient_did[:60]}...")
                LOGGER.error("=" * 80)
                return connection
        except Exception as e:
            LOGGER.error(f"[PQC FIX]   ⚠️  Sender-based lookup failed: {e}")

    # Step 3: Fall back to recipient-based lookup (original behavior)
    LOGGER.error(f"[PQC FIX] Falling back to RECIPIENT-BASED lookup...")
    if receipt.recipient_verkey:
        try:
            LOGGER.error(f"[PQC FIX] Getting wallet and calling get_local_did_for_verkey...")
            async with self._profile.session() as session:
                wallet = session.inject(BaseWallet)
                my_info = await wallet.get_local_did_for_verkey(
                    receipt.recipient_verkey
                )
            LOGGER.error(f"[PQC FIX]   Got my_info.did: {my_info.did[:60]}...")
            receipt.recipient_did = my_info.did
            if "posted" in my_info.metadata and my_info.metadata["posted"] is True:
                receipt.recipient_did_public = True
                LOGGER.error(f"[PQC FIX]   Set recipient_did_public = True")
        except InjectionError as e:
            LOGGER.error(f"[PQC FIX]   ❌ InjectionError: {e}")
            self._logger.warning(
                "Cannot resolve recipient verkey, no wallet defined by context: %s",
                receipt.recipient_verkey,
            )
        except WalletNotFoundError as e:
            LOGGER.error(f"[PQC FIX]   ⚠️  WalletNotFoundError: {e}")
            self._logger.debug(
                "No corresponding DID found for recipient verkey: %s",
                receipt.recipient_verkey,
            )

    LOGGER.error(f"[PQC FIX]   Final sender_did: {receipt.sender_did[:60] if receipt.sender_did else 'None'}...")
    LOGGER.error(f"[PQC FIX]   Final recipient_did: {receipt.recipient_did[:60] if receipt.recipient_did else 'None'}...")
    LOGGER.error("[PQC FIX] Calling find_connection with both DIDs...")

    result = await self.find_connection(
        receipt.sender_did, receipt.recipient_did, receipt.parent_thread_id, True
    )

    LOGGER.error(f"[PQC FIX]   find_connection result: {result}")
    LOGGER.error("[PQC FIX] resolve_inbound_connection DONE")
    LOGGER.error("=" * 80)

    return result


async def find_connection_pqc(
    self,
    their_did: Optional[str],
    my_did: Optional[str] = None,
    parent_thread_id: Optional[str] = None,
    auto_complete=False,
):
    """PQC-aware version of find_connection that handles both long and short forms of my_did.

    CRITICAL FIX for credential offer handling:
    - Connection is stored with my_did = LONG-FORM during DID Exchange
    - Credential offer processing uses my_did = SHORT-FORM (from wallet.get_local_did_for_verkey)
    - Original find_connection only queries with the exact my_did provided → NOT FOUND!

    This patch:
    1. Converts my_did to both long and short forms (if did:peer:4)
    2. Queries database with: (their_did IN (long, short)) AND (my_did IN (long, short))
    3. Returns the connection if found

    This matches the existing logic for their_did in base_manager.py:897-907.

    Args:
        self: BaseConnectionManager instance
        their_did: Their DID
        my_did: My DID (can be long or short form for did:peer:4)
        parent_thread_id: Parent thread ID
        auto_complete: Should this connection automatically be promoted to active

    Returns:
        The located `ConnRecord`, if any
    """
    from acapy_agent.storage.error import StorageNotFoundError
    from acapy_agent.connections.models.conn_record import ConnRecord
    from acapy_agent.protocols.discovery.v2_0.manager import V20DiscoveryMgr
    from did_peer_4 import long_to_short

    LOGGER.error("=" * 80)
    LOGGER.error("[PQC FIX] find_connection_pqc CALLED")
    LOGGER.error(f"[PQC FIX]   their_did: {their_did[:60] if their_did else 'None'}...")
    LOGGER.error(f"[PQC FIX]   my_did: {my_did[:60] if my_did else 'None'}...")
    LOGGER.error(f"[PQC FIX]   parent_thread_id: {parent_thread_id}")

    connection = None
    if their_did and their_did.startswith("did:peer:4"):
        # Handle their_did: Convert to both long and short forms
        their_long = their_did
        their_short = self.long_did_peer_to_short(their_did)
        LOGGER.error(f"[PQC FIX]   their_did_long: {their_long[:60]}...")
        LOGGER.error(f"[PQC FIX]   their_did_short: {their_short[:60]}...")

        # CRITICAL FIX: Also handle my_did in both forms!
        if my_did and my_did.startswith("did:peer:4"):
            # Check if my_did is already long-form (contains ":z")
            if ":z" in my_did:
                my_long = my_did
                my_short = long_to_short(my_did)
            else:
                # my_did is short-form, need to find long-form
                # For now, we'll search with just short form and also try to
                # reconstruct long form from wallet
                my_short = my_did
                my_long = None  # We'll handle this with $or query

                # Try to get long form from wallet
                try:
                    async with self._profile.session() as session:
                        wallet = session.inject(BaseWallet)
                        # Check if there's a long-form version stored
                        try:
                            my_did_info = await wallet.get_local_did(my_did)
                            # If successful, my_did exists (short form is valid)
                        except Exception:
                            pass
                except Exception as e:
                    LOGGER.debug(f"Could not retrieve long form for my_did: {e}")

            LOGGER.error(f"[PQC FIX]   my_did is did:peer:4")
            LOGGER.error(f"[PQC FIX]   my_did_short: {my_short[:60]}...")
            LOGGER.error(f"[PQC FIX]   my_did_long: {my_long[:60] if my_long else 'None (will search all)'}...")

            # Query with both forms of their_did AND my_did
            try:
                async with self._profile.session() as session:
                    # Build query that checks:
                    # (their_did = long OR their_did = short) AND (my_did = short OR my_did = long)
                    # Since we might not have my_long, we'll search for connections with
                    # matching their_did first, then filter by my_did
                    LOGGER.error(f"[PQC FIX]   Querying with retrieve_by_did_peer_4...")

                    # Try with short my_did first
                    try:
                        connection = await ConnRecord.retrieve_by_did_peer_4(
                            session, their_long, their_short, my_short
                        )
                        LOGGER.error(f"[PQC FIX]   ✅ Found connection with my_did={my_short[:60]}...")
                    except StorageNotFoundError:
                        # If short form fails and we have long form, try long form
                        if my_long:
                            LOGGER.error(f"[PQC FIX]   Short form failed, trying long form...")
                            try:
                                connection = await ConnRecord.retrieve_by_did_peer_4(
                                    session, their_long, their_short, my_long
                                )
                                LOGGER.error(f"[PQC FIX]   ✅ Found connection with my_did={my_long[:60]}...")
                            except StorageNotFoundError:
                                LOGGER.error(f"[PQC FIX]   ❌ Long form also failed")
                                LOGGER.error(f"[PQC FIX]   Connection NOT FOUND (as expected - wrong my_did from wallet)")
            except StorageNotFoundError:
                LOGGER.error(f"[PQC FIX]   ❌ No connection found (StorageNotFoundError)")
                pass
        else:
            # my_did is not did:peer:4, use original logic
            LOGGER.error(f"[PQC FIX]   my_did is not did:peer:4, using original query")
            try:
                async with self._profile.session() as session:
                    connection = await ConnRecord.retrieve_by_did_peer_4(
                        session, their_long, their_short, my_did
                    )
                LOGGER.error(f"[PQC FIX]   ✅ Found connection")
            except StorageNotFoundError:
                LOGGER.error(f"[PQC FIX]   ❌ No connection found")
                pass
    elif their_did:
        # their_did is not did:peer:4, use original logic
        LOGGER.error(f"[PQC FIX]   their_did is not did:peer:4, using original retrieve_by_did")
        try:
            async with self._profile.session() as session:
                connection = await ConnRecord.retrieve_by_did(
                    session, their_did, my_did
                )
            LOGGER.error(f"[PQC FIX]   ✅ Found connection")
        except StorageNotFoundError:
            LOGGER.error(f"[PQC FIX]   ❌ No connection found")
            pass

    # Handle auto_complete (from original base_manager.py:917-934)
    if (
        connection
        and ConnRecord.State.get(connection.state) is ConnRecord.State.RESPONSE
        and auto_complete
    ):
        LOGGER.error(f"[PQC FIX]   Auto-completing connection to COMPLETED state")
        connection.state = ConnRecord.State.COMPLETED.rfc160
        async with self._profile.session() as session:
            await connection.save(session, reason="Connection promoted to active")
            if session.settings.get("auto_disclose_features"):
                discovery_mgr = V20DiscoveryMgr(self._profile)
                await discovery_mgr.proactive_disclose_features(
                    connection_id=connection.connection_id
                )

    LOGGER.error(f"[PQC FIX]   Result: {'Found' if connection else 'None'}")
    if connection:
        LOGGER.error(f"[PQC FIX]     connection_id: {connection.connection_id}")
        LOGGER.error(f"[PQC FIX]     their_did: {connection.their_did[:60]}...")
        LOGGER.error(f"[PQC FIX]     my_did: {connection.my_did[:60]}...")
    LOGGER.error("[PQC FIX] find_connection_pqc DONE")
    LOGGER.error("=" * 80)

    return connection

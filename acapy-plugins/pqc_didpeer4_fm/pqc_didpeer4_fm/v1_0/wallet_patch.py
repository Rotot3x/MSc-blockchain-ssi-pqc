"""Patch for acapy_agent/wallet/askar.py to support PQC key lookup.

This patch extends AskarWallet.get_local_did_for_verkey to handle did:peer:4 DIDs
with multiple keys (ML-DSA-65 for authentication, ML-KEM-768 for key agreement).

CRITICAL FIX for connection lookup during message handling:
- DIDs are stored with verkey=ML-DSA-65 (authentication key, #key-0)
- DIDComm encrypts messages with ML-KEM-768 (keyAgreement key, #key-1)
- When credential offer arrives, receipt.recipient_verkey = ML-KEM-768
- Original wallet.get_local_did_for_verkey(ML-KEM-768) throws WalletNotFoundError
- Connection lookup fails → "No connection found" error!

This patch:
1. Tries the original lookup (searches for verkey in tags)
2. On WalletNotFoundError: Searches for DIDs where metadata.kem_verkey == verkey
3. Returns the DID if found

This enables connection lookup for incoming DIDComm messages encrypted with ML-KEM-768!
"""

import logging
from typing import TYPE_CHECKING

from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import KeyType

if TYPE_CHECKING:
    from acapy_agent.wallet.askar import AskarWallet

LOGGER = logging.getLogger(__name__)


async def get_local_did_for_verkey_pqc(self: "AskarWallet", verkey: str) -> DIDInfo:
    """Resolve a local DID from a verkey (PQC-aware version).

    This is a patched version of AskarWallet.get_local_did_for_verkey that handles
    PQC did:peer:4 DIDs with multiple keys.

    CRITICAL DIFFERENCE from original (askar.py:462-491):
    - Original: Only searches for DIDs with verkey tag matching the input
    - This version: ALSO searches for DIDs with metadata.kem_verkey matching the input

    This is necessary because:
    - did:peer:4 has TWO keys: ML-DSA-65 (auth) and ML-KEM-768 (keyAgr)
    - DIDs are stored with verkey=ML-DSA-65 tag (only one verkey field in DIDInfo!)
    - DIDComm encrypts with ML-KEM-768 (recipient key for decryption)
    - When message arrives: receipt.recipient_verkey = ML-KEM-768
    - Original method: fetch_all(CATEGORY_DID, {"verkey": ML-KEM-768}) → NOT FOUND!
    - This patch: fetch_all by kem_verkey in metadata → FOUND!

    Args:
        self: AskarWallet instance
        verkey: The verkey for which to get the local DID (can be ML-DSA-65 OR ML-KEM-768)

    Returns:
        A `DIDInfo` instance representing the found DID

    Raises:
        WalletNotFoundError: If the verkey is not found (neither as primary nor as KEM key)
    """
    from aries_askar import AskarError

    LOGGER.error(f"[PQC Patch] ====== WALLET PATCH CALLED ====== verkey: {verkey[:30]}...")

    # Step 1: Try the original lookup (search by verkey tag)
    # This handles classical keys (ED25519) and PQC authentication keys (ML-DSA-65)
    try:
        LOGGER.error(f"[PQC Patch] Trying primary verkey lookup...")
        dids = await self._session.handle.fetch_all("did", {"verkey": verkey})
    except AskarError as err:
        from acapy_agent.wallet.error import WalletError
        raise WalletError("Error when fetching local DID for verkey") from err

    if dids:
        LOGGER.error(f"[PQC Patch] ✅ Found {len(dids)} DID(s) with primary verkey → returning first")
        ret_did = dids[0]
        ret_did_info = ret_did.value_json
        # Handle long/short form preference (original logic from askar.py:483-489)
        if len(dids) > 1 and ret_did_info["did"].startswith("did:peer:4"):
            other_did = dids[1]
            other_did_info = other_did.value_json
            if len(other_did_info["did"]) < len(ret_did_info["did"]):
                ret_did = other_did
                ret_did_info = other_did.value_json
        return self._load_did_entry(ret_did)

    # Step 2: Primary verkey not found - check if it's a KEM verkey for a PQC DID
    LOGGER.error(f"[PQC Patch] Primary verkey NOT FOUND → Checking for KEM verkey in metadata...")

    try:
        # Fetch ALL DIDs (we need to check metadata, which isn't indexed)
        all_dids = await self._session.handle.fetch_all("did")
    except AskarError as err:
        from acapy_agent.wallet.error import WalletError
        raise WalletError("Error when fetching DIDs for KEM verkey lookup") from err

    # Search for DIDs with kem_verkey in metadata matching our verkey
    for did_entry in all_dids:
        did_info_json = did_entry.value_json
        # metadata is stored INSIDE value_json (not as separate Entry attribute!)
        metadata = did_info_json.get("metadata", {})

        # Check if this DID has a kem_verkey that matches our search
        if metadata.get("kem_verkey") == verkey:
            LOGGER.error(f"[PQC Patch] ✅✅✅ FOUND DID WITH KEM VERKEY ✅✅✅")
            LOGGER.error(f"[PQC Patch]    DID: {did_info_json['did'][:60]}...")
            LOGGER.error(f"[PQC Patch]    Primary verkey (ML-DSA-65): {did_info_json['verkey'][:30]}...")
            LOGGER.error(f"[PQC Patch]    KEM verkey (ML-KEM-768): {verkey[:30]}...")
            return self._load_did_entry(did_entry)

    # Step 3: Neither primary nor KEM verkey found
    LOGGER.error(f"[PQC Patch] ❌❌❌ NO DID FOUND ❌❌❌ (neither primary nor KEM)")
    LOGGER.error(f"[PQC Patch] Searched {len(all_dids)} DIDs in wallet - none matched!")
    raise WalletNotFoundError(f"No DID defined for verkey: {verkey}")

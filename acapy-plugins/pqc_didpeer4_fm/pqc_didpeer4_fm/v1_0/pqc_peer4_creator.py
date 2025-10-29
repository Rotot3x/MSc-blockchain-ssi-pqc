"""Create did:peer:4 with ML-DSA-65 + ML-KEM-768."""

from typing import List, Optional, Sequence, Dict
from did_peer_4 import encode
from did_peer_4.input_doc import input_doc_from_keys_and_services, KeySpec

from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.did_method import PEER4

from .key_types import ML_DSA_65, ML_KEM_768
from .pqc_multikey import key_info_to_multikey


async def create_pqc_peer4_did(
    wallet: BaseWallet,
    svc_endpoints: Optional[Sequence[str]] = None,
    routing_keys: Optional[List[str]] = None,
    metadata: Optional[Dict] = None,
) -> DIDInfo:
    """Create did:peer:4 with ML-DSA-65 (signature) + ML-KEM-768 (key agreement).

    This function creates a PQC-enabled did:peer:4 DID with two keys:
    1. ML-DSA-65 for authentication and assertion (digital signatures)
    2. ML-KEM-768 for key agreement (encryption/key encapsulation)

    Args:
        wallet: Wallet instance for key management
        svc_endpoints: Service endpoints for DIDComm messaging
        routing_keys: Routing keys for mediation (optional)
        metadata: Additional metadata to store with DID

    Returns:
        DIDInfo compatible with GET /wallet/did response format

    Example:
        >>> did_info = await create_pqc_peer4_did(
        ...     wallet=wallet,
        ...     svc_endpoints=["https://agent.example.com:8020"]
        ... )
        >>> print(did_info.did)
        did:peer:4:z6MNxxx...
    """

    # 1. Create ML-DSA-65 key (signature/authentication)
    sig_key = await wallet.create_key(ML_DSA_65)

    # 2. Create ML-KEM-768 key (key agreement/encryption)
    kem_key = await wallet.create_key(ML_KEM_768)

    # 3. Convert to multikeys
    sig_multikey = key_info_to_multikey(sig_key)  # → z6MN... (ML-DSA-65)
    kem_multikey = key_info_to_multikey(kem_key)  # → z6MK768... (ML-KEM-768)

    # 4. Create KeySpec objects for did:peer:4
    # NOTE: Order matters! did-peer-4 numbers from 0: key_specs[0] → #key-0, key_specs[1] → #key-1
    key_specs = [
        KeySpec(
            multikey=sig_multikey,
            relationships=["authentication", "assertionMethod"]  # → #key-0
        ),
        KeySpec(
            multikey=kem_multikey,
            relationships=["keyAgreement"]  # → #key-1 (used in recipientKeys!)
        ),
    ]

    # 5. Build DIDComm v1 services (compatible with DID Exchange 1.1)
    services = []
    for index, endpoint in enumerate(svc_endpoints or []):
        services.append({
            "id": f"#didcomm-{index}",
            "type": "did-communication",
            "recipientKeys": ["#key-1"],  # ML-KEM-768 (key agreement/encryption, key_specs[1] → #key-1)
            "routingKeys": routing_keys or [],
            "serviceEndpoint": endpoint,
            "priority": index,
        })

    # 6. Generate did:peer:4 (long form)
    input_doc = input_doc_from_keys_and_services(
        keys=key_specs,
        services=services
    )
    did = encode(input_doc)

    # 7. Create metadata (compatible with existing /wallet/did format)
    did_metadata = metadata or {}
    did_metadata.update({
        "pqc_enabled": True,
        "signature_algorithm": "ml-dsa-65",
        "key_agreement_algorithm": "ml-kem-768",
        "kem_key_kid": f"{did}#key-1",  # KEM key is key_specs[1] → #key-1
        "plugin": "pqc_didpeer4_fm",
        "version": "0.1.0",
    })

    # 8. Create DIDInfo (SAME structure as original did:peer:4!)
    did_info = DIDInfo(
        did=did,
        method=PEER4,
        verkey=sig_key.verkey,
        metadata=did_metadata,
        key_type=ML_DSA_65,
    )

    # 9. Store DID in wallet
    await wallet.store_did(did_info)

    # 10. Assign Key IDs - did-peer-4 numbers from 0!
    await wallet.assign_kid_to_key(sig_key.verkey, f"{did}#key-0")  # key_specs[0] → #key-0
    await wallet.assign_kid_to_key(kem_key.verkey, f"{did}#key-1")  # key_specs[1] → #key-1

    return did_info

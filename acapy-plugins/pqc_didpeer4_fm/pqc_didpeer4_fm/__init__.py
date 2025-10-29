"""pqc_didpeer4_fm - Post-Quantum did:peer:4 Plugin by Ferris Menzel.

Transparently replaces ED25519/X25519 with ML-DSA-65/ML-KEM-768 in did:peer:4.
NO API changes needed - works with existing workflows!
"""

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.resolver.did_resolver import DIDResolver

from .v1_0.pqc_multicodec import register_pqc_multicodecs
from .v1_0.multicodec_patch import patch_supported_codecs
from .v1_0.monkey_patches import apply_all_patches
from .v1_0.pqc_peer4_resolver import PQCPeer4Resolver
from .v1_0.askar_pqc_patch import (
    patch_askar_create_keypair,
    patch_askar_pack_unpack,
    patch_attach_decorator_for_pqc,
)
from .v1_0.validator_patch import patch_jws_header_kid_for_peer4
from .v1_0.wallet_patch import get_local_did_for_verkey_pqc
from .v1_0.connection_target_patch import patch_connection_target_schema

__version__ = "0.1.0"
__author__ = "Ferris Menzel"


async def setup(context: InjectionContext):
    """Setup pqc_didpeer4_fm plugin.

    This plugin transparently replaces ED25519/X25519 with ML-DSA-65/ML-KEM-768
    in did:peer:4 creation. NO API changes needed!
    """
    print("=" * 60)
    print("🔐 pqc_didpeer4_fm Plugin v0.1.0")
    print("   Post-Quantum did:peer:4 with ML-DSA-65 + ML-KEM-768")
    print("   by Ferris Menzel")
    print("=" * 60)

    # 1. Patch aries-askar for PQC key generation support
    patch_askar_create_keypair()
    print("   ✅ Askar patched for PQC key generation (liboqs-python)")

    # 2. Register PQC key types and patch ACA-Py internals
    from .v1_0.key_type_patches import (
        register_pqc_key_types,
        patch_api_key_type_schemas,
        patch_did_peer4_supported_key_types,
        patch_alg_mappings_for_pqc,
    )
    register_pqc_key_types(context)
    patch_api_key_type_schemas()
    patch_did_peer4_supported_key_types(context)
    patch_alg_mappings_for_pqc()

    # 3. Register PQC multicodecs and patch SupportedCodecs
    register_pqc_multicodecs()
    patch_supported_codecs()
    print("   ✅ PQC Multicodecs registered (ML-DSA-65, ML-KEM-768)")
    print("   ✅ SupportedCodecs patched for PQC multicodec decoding")

    # 4. Patch DIDComm v1 pack/unpack for PQC support
    patch_askar_pack_unpack()
    print("   ✅ DIDComm v1 pack/unpack patched for ML-KEM-768")

    # 5. Patch AttachDecorator for PQC JWS signatures (DID Exchange)
    patch_attach_decorator_for_pqc()
    print("   ✅ AttachDecorator patched for ML-DSA-65 JWS signatures")

    # 5.5. Patch JWSHeaderKid validator to accept did:peer:4 format
    patch_jws_header_kid_for_peer4()
    print("   ✅ JWSHeaderKid validator patched for did:peer:4")

    # 5.6. Patch AskarWallet.get_local_did_for_verkey for PQC KEM verkey lookup
    from acapy_agent.wallet.askar import AskarWallet
    import logging
    LOGGER = logging.getLogger(__name__)

    # Store original for verification
    original_method = AskarWallet.get_local_did_for_verkey
    AskarWallet.get_local_did_for_verkey = get_local_did_for_verkey_pqc

    # Verify patch was applied
    if AskarWallet.get_local_did_for_verkey == get_local_did_for_verkey_pqc:
        print("   ✅ AskarWallet patched for ML-KEM-768 verkey lookup")
        LOGGER.error("🔧 WALLET PATCH APPLIED SUCCESSFULLY AT PLUGIN LOAD")
        LOGGER.error(f"   Original: {original_method}")
        LOGGER.error(f"   Patched:  {AskarWallet.get_local_did_for_verkey}")
    else:
        print("   ❌ WARNING: AskarWallet patch failed to apply!")
        LOGGER.error("❌ WALLET PATCH FAILED TO APPLY!")
        raise RuntimeError("AskarWallet patch verification failed")

    # 5.7. Patch ConnectionTarget schema to accept PQC keys (credential issuance fix)
    patch_connection_target_schema()
    print("   ✅ ConnectionTarget schema patched for PQC key validation")

    # 6. Apply monkey patches (transparent replacement)
    apply_all_patches()
    print("   ✅ Monkey patches applied to BaseConnectionManager")
    print("      - create_did_peer_4 → PQC version (eliminates ED25519)")
    print("      - _extract_key_material_in_base58_format → PQC support")
    print("      - long_did_peer_4_to_short → Preserves PQC key_type")
    print("      - long_did_peer_to_short → Handles short-form DIDs correctly")
    print("      - record_keys_for_resolvable_did → Stores BOTH PQC keys")
    print("      - resolve_inbound_connection → DEBUG logging for diagnostics")
    print("      - find_connection → Handles long/short form my_did (credential fix)")

    # 7. Register PQC resolver
    resolver = context.inject(DIDResolver)
    resolver.register_resolver(PQCPeer4Resolver())
    print("   ✅ PQC Peer4 Resolver registered")

    print("=" * 60)
    print("🎉 pqc_didpeer4_fm loaded successfully!")
    print("   did:peer:4 now uses ML-DSA-65 + ML-KEM-768")
    print("=" * 60)
    print()

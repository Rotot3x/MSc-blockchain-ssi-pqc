"""Patches for KeyTypes Registry and API Schema Validation.

This module extends ACA-Py's KeyTypes registry and API schemas to support
PQC key types (ML-DSA-65, ML-KEM-768).
"""

import logging

LOGGER = logging.getLogger(__name__)


def register_pqc_key_types(context):
    """Register PQC KeyTypes in ACA-Py's global KeyTypes registry.

    Args:
        context: InjectionContext to inject KeyTypes singleton

    This allows all ACA-Py components to look up PQC key types via:
    - key_types.from_key_type("ml-dsa-65")
    - key_types.from_multicodec_name("ml-dsa-65-pub")
    - key_types.from_multicodec_prefix(b"\xd0\x65")
    """
    from acapy_agent.wallet.key_type import KeyTypes

    from .key_types import ML_DSA_65, ML_KEM_768

    try:
        key_types = context.inject(KeyTypes)

        # Register PQC key types
        key_types.register(ML_DSA_65)
        key_types.register(ML_KEM_768)

        LOGGER.info(
            "Registered PQC key types in KeyTypes registry: ml-dsa-65, ml-kem-768"
        )
        print("   ✅ Registered ML-DSA-65 and ML-KEM-768 in KeyTypes registry")

    except Exception as e:
        LOGGER.error(f"Failed to register PQC key types: {e}")
        raise


def patch_api_key_type_schemas():
    """Patch Marshmallow Schema __init__ to inject PQC validators at runtime.

    Patches 3 schema classes in acapy_agent/wallet/routes.py:
    1. DIDSchema.key_type (line 135) - Response schema
    2. DIDListQueryStringSchema.key_type (line 335) - Query parameter
    3. DIDCreateOptionsSchema.key_type (line 355) - Request body

    This allows:
    - POST /wallet/did/create with {"options": {"key_type": "ml-dsa-65"}}
    - GET /wallet/did?key_type=ml-dsa-65

    NOTE: We patch __init__() because aiohttp-apispec creates schema instances
    AFTER plugin setup. Patching _declared_fields doesn't work because
    Marshmallow copies them during instantiation.
    """
    from marshmallow import validate

    from acapy_agent.wallet.routes import (
        DIDCreateOptionsSchema,
        DIDListQueryStringSchema,
        DIDSchema,
    )

    try:
        # New validator including PQC key types
        pqc_validator = validate.OneOf(
            [
                "ed25519",
                "bls12381g2",
                "p256",
                "ml-dsa-65",
                "ml-kem-768",
            ]
        )

        # Patch 1: DIDSchema (response schema for /wallet/did, /wallet/did/create)
        original_did_init = DIDSchema.__init__

        def patched_did_init(self, *args, **kwargs):
            original_did_init(self, *args, **kwargs)
            if "key_type" in self.fields:
                self.fields["key_type"].validators = [pqc_validator]

        DIDSchema.__init__ = patched_did_init

        # Patch 2: DIDListQueryStringSchema (query params for GET /wallet/did)
        original_list_init = DIDListQueryStringSchema.__init__

        def patched_list_init(self, *args, **kwargs):
            original_list_init(self, *args, **kwargs)
            if "key_type" in self.fields:
                self.fields["key_type"].validators = [pqc_validator]

        DIDListQueryStringSchema.__init__ = patched_list_init

        # Patch 3: DIDCreateOptionsSchema (CRITICAL: request body for POST /wallet/did/create)
        original_create_init = DIDCreateOptionsSchema.__init__

        def patched_create_init(self, *args, **kwargs):
            original_create_init(self, *args, **kwargs)
            if "key_type" in self.fields:
                self.fields["key_type"].validators = [pqc_validator]

        DIDCreateOptionsSchema.__init__ = patched_create_init

        LOGGER.info("Patched API schemas __init__ to accept PQC key_types at runtime")
        print("   ✅ Patched API schemas for PQC key_types (ml-dsa-65, ml-kem-768)")

    except Exception as e:
        LOGGER.error(f"Failed to patch API schemas: {e}")
        raise


def patch_did_peer4_supported_key_types(context):
    """Extend PEER4 DIDMethod to support PQC key types.

    By default, PEER4 only supports [ED25519, X25519].
    This patch adds [ML_DSA_65, ML_KEM_768] to make did:peer:4 PQC-capable.

    This is required because wallet_create_did() checks:
        if not method.supports_key_type(key_type):
            raise HTTPForbidden(...)

    Args:
        context: InjectionContext (unused, for API consistency)
    """
    from acapy_agent.wallet.did_method import PEER4

    from .key_types import ML_DSA_65, ML_KEM_768

    try:
        # Extend PEER4's supported key types
        # Original: [ED25519, X25519]
        # After patch: [ED25519, X25519, ML_DSA_65, ML_KEM_768]
        PEER4._supported_key_types.extend([ML_DSA_65, ML_KEM_768])

        supported_types = [kt.key_type for kt in PEER4.supported_key_types]
        LOGGER.info(f"Extended PEER4 to support PQC key types: {supported_types}")
        print(f"   ✅ PEER4 now supports: {supported_types}")

    except Exception as e:
        LOGGER.error(f"Failed to patch PEER4 supported key types: {e}")
        raise


def patch_alg_mappings_for_pqc():
    """Extend ALG_MAPPINGS in wallet/keys/manager.py for PQC multikey support.

    ALG_MAPPINGS is used by verkey_to_multikey() and multikey_to_verkey()
    to convert between base58 verkeys and multibase multikeys.

    Without this patch, wallet.create_key(ML_DSA_65) fails with:
        KeyError: 'ml-dsa-65' in ALG_MAPPINGS[alg]["prefix_hex"]
    """
    from acapy_agent.wallet.keys.manager import ALG_MAPPINGS

    from .key_types import ML_DSA_65, ML_KEM_768

    try:
        # Add PQC algorithms to ALG_MAPPINGS
        # Based on multicodec prefixes from pqc_multicodec.py
        ALG_MAPPINGS["ml-dsa-65"] = {
            "key_type": ML_DSA_65,
            "multikey_prefix": "z6MN",  # Will be different for ML-DSA, but use z6MN for now
            "prefix_hex": "d065",  # From PQC_MULTICODECS: b"\xd0\x65"
            "prefix_length": 2,
        }

        ALG_MAPPINGS["ml-kem-768"] = {
            "key_type": ML_KEM_768,
            "multikey_prefix": "z6Ls",  # Will be different for ML-KEM
            "prefix_hex": "e018",  # From PQC_MULTICODECS: b"\xe0\x18"
            "prefix_length": 2,
        }

        LOGGER.info("Extended ALG_MAPPINGS for PQC multikey conversion")
        print("   ✅ ALG_MAPPINGS extended for PQC (ml-dsa-65, ml-kem-768)")

    except Exception as e:
        LOGGER.error(f"Failed to patch ALG_MAPPINGS: {e}")
        raise

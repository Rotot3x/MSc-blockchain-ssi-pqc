"""Admin API routes for PQCrypto_FM Plugin."""

import logging
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields, Schema, validate

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import UUIDFour
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.error import WalletError, WalletNotFoundError

from .services.pqc_crypto_service import PQCCryptoService
from .services.pqc_wallet_service import PQCWalletService
from .services.pqc_did_service import PQCDidService
from .key_types import PQC_KEY_TYPES, get_signature_key_types, get_kem_key_types

LOGGER = logging.getLogger(__name__)


# Helper Functions

async def _initialize_all_services(context):
    """Initialize all PQC services together to handle dependencies."""
    from .config import PQCConfig
    from .services.pqc_crypto_service import PQCCryptoService
    from .services.pqc_wallet_service import PQCWalletService
    from .services.pqc_did_service import PQCDidService

    # Check if already initialized
    if context.inject_or(PQCCryptoService) and context.inject_or(PQCWalletService) and context.inject_or(PQCDidService):
        return

    config = PQCConfig(context.settings)

    # Initialize crypto service first (dependency for others)
    crypto_service = PQCCryptoService(config)
    await crypto_service.initialize()
    context.injector.bind_instance(PQCCryptoService, crypto_service)

    # Initialize wallet service
    wallet_service = PQCWalletService(config)
    context.injector.bind_instance(PQCWalletService, wallet_service)

    # Initialize DID service
    did_service = PQCDidService(config)
    context.injector.bind_instance(PQCDidService, did_service)


async def get_crypto_service(context) -> PQCCryptoService:
    """Get or create PQC crypto service."""
    crypto_service = context.inject_or(PQCCryptoService)
    if not crypto_service:
        # Initialize all PQC services together to handle dependencies
        await _initialize_all_services(context)
        crypto_service = context.inject(PQCCryptoService)
    return crypto_service


async def get_wallet_service(context) -> PQCWalletService:
    """Get or create PQC wallet service."""
    wallet_service = context.inject_or(PQCWalletService)
    if not wallet_service:
        # Initialize all PQC services together to handle dependencies
        await _initialize_all_services(context)
        wallet_service = context.inject(PQCWalletService)
    return wallet_service


async def get_did_service(context) -> PQCDidService:
    """Get or create PQC DID service."""
    did_service = context.inject_or(PQCDidService)
    if not did_service:
        # Initialize all PQC services together to handle dependencies
        await _initialize_all_services(context)
        did_service = context.inject(PQCDidService)
    return did_service


# Request/Response Schemas

class PQCKeyCreateRequestSchema(OpenAPISchema):
    """Schema for PQC key creation request."""

    key_type = fields.Str(
        required=True,
        validate=validate.OneOf([kt.key_type for kt in PQC_KEY_TYPES]),
        metadata={"description": "Type of PQC key to create", "example": "ml-dsa-65"}
    )
    seed = fields.Str(
        required=False,
        metadata={"description": "Optional seed for key generation", "example": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
    )
    metadata = fields.Dict(
        required=False,
        metadata={"description": "Optional metadata for the key", "example": {"purpose": "signing", "algorithm": "ML-DSA-65", "created_at": "2025-09-22T07:00:00Z"}}
    )
    kid = fields.Str(
        required=False,
        metadata={"description": "Optional key identifier", "example": "pqc-key-001"}
    )


class PQCKeyInfoSchema(OpenAPISchema):
    """Schema for PQC key information."""

    verkey = fields.Str(
        required=True,
        metadata={"description": "Verification key"}
    )
    key_type = fields.Str(
        required=True,
        metadata={"description": "Key type"}
    )
    metadata = fields.Dict(
        required=False,
        metadata={"description": "Key metadata"}
    )


class PQCKeyListSchema(OpenAPISchema):
    """Schema for PQC key list response."""

    keys = fields.List(
        fields.Nested(PQCKeyInfoSchema),
        required=True,
        metadata={"description": "List of PQC keys"}
    )


class PQCDidCreateRequestSchema(OpenAPISchema):
    """Schema for PQC DID creation request."""

    method = fields.Str(
        required=False,
        validate=validate.OneOf(["pqc", "hybrid"]),
        metadata={"description": "DID method (defaults to config setting)", "example": "pqc"}
    )
    key_type = fields.Str(
        required=False,
        validate=validate.OneOf([kt.key_type for kt in get_signature_key_types()]),
        metadata={"description": "Key type for DID (defaults to config setting)", "example": "ml-dsa-65"}
    )
    seed = fields.Str(
        required=False,
        metadata={"description": "Optional seed for key generation", "example": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
    )
    metadata = fields.Dict(
        required=False,
        metadata={"description": "Optional metadata for the DID", "example": {"purpose": "authentication", "description": "PQC DID for secure communications"}}
    )


class PQCDidInfoSchema(OpenAPISchema):
    """Schema for PQC DID information."""

    did = fields.Str(
        required=True,
        metadata={"description": "DID string"}
    )
    verkey = fields.Str(
        required=True,
        metadata={"description": "Verification key"}
    )
    method = fields.Str(
        required=True,
        metadata={"description": "DID method"}
    )
    key_type = fields.Str(
        required=True,
        metadata={"description": "Key type"}
    )
    metadata = fields.Dict(
        required=False,
        metadata={"description": "DID metadata"}
    )


class PQCDidListSchema(OpenAPISchema):
    """Schema for PQC DID list response."""

    dids = fields.List(
        fields.Nested(PQCDidInfoSchema),
        required=True,
        metadata={"description": "List of PQC DIDs"}
    )


class PQCSignRequestSchema(OpenAPISchema):
    """Schema for PQC signing request."""

    verkey = fields.Str(
        required=True,
        metadata={"description": "Verification key of signing key"}
    )
    message = fields.Str(
        required=True,
        metadata={"description": "Message to sign (base64 encoded)"}
    )


class PQCSignResponseSchema(OpenAPISchema):
    """Schema for PQC signing response."""

    signature = fields.Str(
        required=True,
        metadata={"description": "Signature (base64 encoded)"}
    )
    algorithm = fields.Str(
        required=True,
        metadata={"description": "Signature algorithm used"}
    )


class PQCVerifyRequestSchema(OpenAPISchema):
    """Schema for PQC verification request."""

    verkey = fields.Str(
        required=True,
        metadata={"description": "Verification key"}
    )
    message = fields.Str(
        required=True,
        metadata={"description": "Original message (base64 encoded)"}
    )
    signature = fields.Str(
        required=True,
        metadata={"description": "Signature to verify (base64 encoded)"}
    )
    algorithm = fields.Str(
        required=True,
        metadata={"description": "Signature algorithm"}
    )


class PQCVerifyResponseSchema(OpenAPISchema):
    """Schema for PQC verification response."""

    valid = fields.Bool(
        required=True,
        metadata={"description": "Whether signature is valid"}
    )


class PQCAlgorithmsResponseSchema(OpenAPISchema):
    """Schema for available algorithms response."""

    signature = fields.List(
        fields.Str(),
        required=True,
        metadata={"description": "Available signature algorithms"}
    )
    kem = fields.List(
        fields.Str(),
        required=True,
        metadata={"description": "Available KEM algorithms"}
    )


class PQCDidMatchInfoSchema(OpenAPISchema):
    """Path parameters for DID operations."""

    did = fields.Str(
        required=True,
        metadata={"description": "DID string"}
    )


class PQCKeyMatchInfoSchema(OpenAPISchema):
    """Path parameters for key operations."""

    verkey = fields.Str(
        required=True,
        metadata={"description": "Verification key"}
    )


# Route Handlers

@docs(
    tags=["pqcrypto_fm"],
    summary="Get available PQC algorithms"
)
@response_schema(PQCAlgorithmsResponseSchema(), 200)
@tenant_authentication
async def get_algorithms(request: web.BaseRequest):
    """Get available PQC algorithms.

    Args:
        request: aiohttp request object

    Returns:
        Available algorithms response
    """
    context: AdminRequestContext = request["context"]
    crypto_service = await get_crypto_service(context)
    algorithms = crypto_service.get_available_algorithms()
    return web.json_response(algorithms)


@docs(
    tags=["pqcrypto_fm"],
    summary="Create a PQC key"
)
@request_schema(PQCKeyCreateRequestSchema())
@response_schema(PQCKeyInfoSchema(), 200)
@tenant_authentication
async def create_key(request: web.BaseRequest):
    """Create a PQC key.

    Args:
        request: aiohttp request object

    Returns:
        Created key information
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    try:
        wallet_service = await get_wallet_service(context)

        # Find key type
        key_type_str = body.get("key_type")
        key_type = None
        for kt in PQC_KEY_TYPES:
            if kt.key_type == key_type_str:
                key_type = kt
                break

        if not key_type:
            raise WalletError(f"Unsupported key type: {key_type_str}")

        key_info = await wallet_service.create_pqc_key(
            context.profile,
            key_type=key_type,
            seed=body.get("seed"),
            metadata=body.get("metadata", {}),
            kid=body.get("kid")
        )

        return web.json_response({
            "verkey": key_info.verkey,
            "key_type": key_info.key_type.key_type,
            "metadata": key_info.metadata or {}
        })

    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="List PQC keys"
)
@response_schema(PQCKeyListSchema(), 200)
@tenant_authentication
async def list_keys(request: web.BaseRequest):
    """List PQC keys.

    Args:
        request: aiohttp request object

    Returns:
        List of PQC keys
    """
    context: AdminRequestContext = request["context"]

    try:
        wallet_service = await get_wallet_service(context)
        key_type_filter = request.query.get("key_type")

        key_infos = await wallet_service.list_pqc_keys(
            context.profile, key_type_filter
        )

        keys = []
        for key_info in key_infos:
            keys.append({
                "verkey": key_info.verkey,
                "key_type": key_info.key_type.key_type,
                "metadata": key_info.metadata or {}
            })

        return web.json_response({"keys": keys})

    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Delete a PQC key"
)
@match_info_schema(PQCKeyMatchInfoSchema())
@tenant_authentication
async def delete_key(request: web.BaseRequest):
    """Delete a PQC key.

    Args:
        request: aiohttp request object

    Returns:
        Empty response
    """
    context: AdminRequestContext = request["context"]
    verkey = request.match_info["verkey"]

    try:
        wallet_service = await get_wallet_service(context)
        await wallet_service.delete_pqc_key(context.profile, verkey)

        return web.json_response({})

    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"Key not found: {verkey}")
    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Sign a message with PQC"
)
@request_schema(PQCSignRequestSchema())
@response_schema(PQCSignResponseSchema(), 200)
@tenant_authentication
async def sign_message(request: web.BaseRequest):
    """Sign a message with PQC.

    Args:
        request: aiohttp request object

    Returns:
        Signature response
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    try:
        import base64

        wallet_service = await get_wallet_service(context)
        crypto_service = await get_crypto_service(context)

        verkey = body.get("verkey")
        message = base64.b64decode(body.get("message"))

        # Get signing key
        keypair, is_hybrid = await wallet_service.get_pqc_signing_key(
            context.profile, verkey
        )

        # Sign message
        if is_hybrid:
            # For hybrid keys, we need special handling
            raise WalletError("Hybrid signing not yet implemented")
        else:
            signature = await crypto_service.sign(message, keypair)

        return web.json_response({
            "signature": base64.b64encode(signature.signature).decode(),
            "algorithm": signature.algorithm
        })

    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"Signing key not found: {body.get('verkey')}")
    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Verify a PQC signature"
)
@request_schema(PQCVerifyRequestSchema())
@response_schema(PQCVerifyResponseSchema(), 200)
@tenant_authentication
async def verify_signature(request: web.BaseRequest):
    """Verify a PQC signature.

    Args:
        request: aiohttp request object

    Returns:
        Verification response
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    try:
        import base64

        crypto_service = await get_crypto_service(context)

        verkey = body.get("verkey")
        message = base64.b64decode(body.get("message"))
        signature_bytes = base64.b64decode(body.get("signature"))
        algorithm = body.get("algorithm")

        # Create signature object
        from .services.pqc_crypto_service import PQCSignature
        signature = PQCSignature(
            signature=signature_bytes,
            algorithm=algorithm,
            public_key=base64.b64decode(verkey)
        )

        # Verify signature
        is_valid = await crypto_service.verify(message, signature)

        return web.json_response({"valid": is_valid})

    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Create a PQC DID"
)
@request_schema(PQCDidCreateRequestSchema())
@response_schema(PQCDidInfoSchema(), 200)
@tenant_authentication
async def create_did(request: web.BaseRequest):
    """Create a PQC DID.

    Args:
        request: aiohttp request object

    Returns:
        Created DID information
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    try:
        did_service = await get_did_service(context)

        method = None
        if body.get("method"):
            from .services.pqc_did_service import PQC_DID_METHOD, HYBRID_DID_METHOD
            if body["method"] == "pqc":
                method = PQC_DID_METHOD
            elif body["method"] == "hybrid":
                method = HYBRID_DID_METHOD

        key_type = body.get("key_type")
        if key_type:
            # Find key type object
            for kt in get_signature_key_types():
                if kt.key_type == key_type:
                    key_type = kt
                    break

        did_info = await did_service.create_pqc_did(
            context.profile,
            method=method,
            key_type=key_type,
            seed=body.get("seed"),
            metadata=body.get("metadata", {})
        )

        return web.json_response({
            "did": did_info.did,
            "verkey": did_info.verkey,
            "method": did_info.method.method_name,
            "key_type": did_info.key_type,
            "metadata": did_info.metadata or {}
        })

    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Get PQC DID information"
)
@match_info_schema(PQCDidMatchInfoSchema())
@response_schema(PQCDidInfoSchema(), 200)
@tenant_authentication
async def get_did(request: web.BaseRequest):
    """Get PQC DID information.

    Args:
        request: aiohttp request object

    Returns:
        DID information
    """
    context: AdminRequestContext = request["context"]
    did = request.match_info["did"]

    try:
        did_service = await get_did_service(context)
        did_info = await did_service.get_pqc_did(context.profile, did)

        return web.json_response({
            "did": did_info.did,
            "verkey": did_info.verkey,
            "method": did_info.method.method_name,
            "key_type": did_info.key_type,
            "metadata": did_info.metadata or {}
        })

    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"DID not found: {did}")
    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Get PQC DID document"
)
@match_info_schema(PQCDidMatchInfoSchema())
@tenant_authentication
async def get_did_document(request: web.BaseRequest):
    """Get PQC DID document.

    Args:
        request: aiohttp request object

    Returns:
        DID document
    """
    context: AdminRequestContext = request["context"]
    did = request.match_info["did"]

    try:
        did_service = await get_did_service(context)
        did_doc = await did_service.get_did_document(context.profile, did)

        return web.json_response(did_doc)

    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"DID not found: {did}")
    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="List PQC DIDs"
)
@response_schema(PQCDidListSchema(), 200)
@tenant_authentication
async def list_dids(request: web.BaseRequest):
    """List PQC DIDs.

    Args:
        request: aiohttp request object

    Returns:
        List of PQC DIDs
    """
    context: AdminRequestContext = request["context"]

    try:
        did_service = await get_did_service(context)
        method_filter = request.query.get("method")

        did_infos = await did_service.list_pqc_dids(
            context.profile, method_filter
        )

        dids = []
        for did_info in did_infos:
            dids.append({
                "did": did_info.did,
                "verkey": did_info.verkey,
                "method": did_info.method.method_name,
                "key_type": did_info.key_type,
                "metadata": did_info.metadata or {}
            })

        return web.json_response({"dids": dids})

    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="Delete a PQC DID"
)
@match_info_schema(PQCDidMatchInfoSchema())
@tenant_authentication
async def delete_did(request: web.BaseRequest):
    """Delete a PQC DID.

    Args:
        request: aiohttp request object

    Returns:
        Empty response
    """
    context: AdminRequestContext = request["context"]
    did = request.match_info["did"]

    try:
        did_service = await get_did_service(context)
        await did_service.delete_pqc_did(context.profile, did)

        return web.json_response({})

    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"DID not found: {did}")
    except (WalletError, StorageError) as e:
        raise web.HTTPBadRequest(reason=str(e))


# =============================================================================
# PQC Askar Wallet Management Schemas and Routes
# =============================================================================

class CreatePQCWalletRequestSchema(OpenAPISchema):
    """Schema for creating a PQC-enabled Askar wallet."""

    wallet_name = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=100),
        metadata={
            "description": "Name for the new PQC wallet",
            "example": "my-pqc-wallet"
        }
    )
    wallet_key = fields.Str(
        required=True,
        validate=validate.Length(min=8),
        metadata={
            "description": "Encryption key for the wallet (minimum 8 characters)",
            "example": "pqc-wallet-key-123"
        }
    )
    label = fields.Str(
        required=False,
        metadata={
            "description": "Optional human-readable label for the wallet",
            "example": "My PQC Wallet"
        }
    )
    image_url = fields.Str(
        required=False,
        metadata={
            "description": "Optional image URL for the wallet",
            "example": "https://example.com/wallet-image.png"
        }
    )
    key_management_mode = fields.Str(
        required=False,
        validate=validate.OneOf(["managed", "unmanaged"]),
        metadata={
            "description": "Key management mode for the wallet",
            "example": "managed"
        }
    )
    wallet_webhook_urls = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "List of webhook URLs for the wallet",
            "example": ["https://example.com/webhook"]
        }
    )
    wallet_dispatch_type = fields.Str(
        required=False,
        validate=validate.OneOf(["default", "base"]),
        metadata={
            "description": "Webhook dispatch type",
            "example": "default"
        }
    )
    pqc_algorithm = fields.Str(
        required=False,
        validate=validate.OneOf([
            "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
            "falcon-512", "falcon-1024",
            "dilithium2", "dilithium3", "dilithium5"
        ]),
        metadata={
            "description": "Default PQC algorithm for the wallet",
            "example": "ml-dsa-65"
        }
    )
    enable_anoncreds = fields.Bool(
        required=False,
        metadata={
            "description": "Enable AnonCreds support in the wallet",
            "example": True
        }
    )
    extra_settings = fields.Dict(
        required=False,
        metadata={
            "description": "Additional wallet settings",
            "example": {"custom_setting": "value"}
        }
    )


class CreatePQCWalletResponseSchema(OpenAPISchema):
    """Schema for PQC wallet creation response."""

    wallet_id = fields.Str(
        metadata={
            "description": "Unique identifier for the created wallet",
            "example": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }
    )
    wallet_info = fields.Dict(
        metadata={
            "description": "Wallet information including PQC configuration"
        }
    )
    token = fields.Str(
        metadata={
            "description": "Authentication token for accessing the wallet",
            "example": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        }
    )
    created_at = fields.Str(
        metadata={
            "description": "Wallet creation timestamp",
            "example": "2023-12-07T12:00:00Z"
        }
    )
    updated_at = fields.Str(
        metadata={
            "description": "Wallet last update timestamp",
            "example": "2023-12-07T12:00:00Z"
        }
    )


class PQCWalletInfoResponseSchema(OpenAPISchema):
    """Schema for PQC wallet information response."""

    wallet_id = fields.Str(
        metadata={
            "description": "Wallet identifier",
            "example": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }
    )
    settings = fields.Dict(
        metadata={
            "description": "Wallet settings"
        }
    )
    pqc_config = fields.Dict(
        metadata={
            "description": "PQC configuration for the wallet"
        }
    )


async def get_askar_wallet_service(context: AdminRequestContext):
    """Get or create PQC Askar Wallet Service."""
    try:
        from .config import PQCConfig
        from .services.pqc_askar_wallet_service import PQCAskarWalletService

        service = context.profile.inject_or(PQCAskarWalletService)
        if not service:
            config = PQCConfig(context.profile.settings)
            service = PQCAskarWalletService(config)
            context.profile.context.injector.bind_instance(PQCAskarWalletService, service)

        return service
    except Exception as e:
        LOGGER.error(f"Failed to get PQC Askar Wallet Service: {e}")
        raise WalletError(f"Service initialization failed: {e}")


@docs(
    tags=["pqcrypto_fm"],
    summary="Create a PQC-enabled Askar wallet"
)
@request_schema(CreatePQCWalletRequestSchema)
@response_schema(CreatePQCWalletResponseSchema(), 200, description="PQC wallet created successfully")
@tenant_authentication
async def create_pqc_wallet(request: web.BaseRequest):
    """Create a new PQC-enabled Askar wallet.

    Args:
        request: aiohttp request object

    Returns:
        JSON response with wallet information and access token
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    try:
        wallet_service = await get_askar_wallet_service(context)

        result = await wallet_service.create_pqc_askar_wallet(
            profile=context.profile,
            wallet_name=body["wallet_name"],
            wallet_key=body["wallet_key"],
            label=body.get("label"),
            image_url=body.get("image_url"),
            key_management_mode=body.get("key_management_mode", "managed"),
            wallet_webhook_urls=body.get("wallet_webhook_urls"),
            wallet_dispatch_type=body.get("wallet_dispatch_type", "default"),
            pqc_algorithm=body.get("pqc_algorithm", "ml-dsa-65"),
            enable_anoncreds=body.get("enable_anoncreds", True),
            extra_settings=body.get("extra_settings")
        )

        return web.json_response(result)

    except WalletError as e:
        raise web.HTTPBadRequest(reason=str(e))
    except Exception as e:
        LOGGER.error(f"Unexpected error creating PQC wallet: {e}")
        raise web.HTTPInternalServerError(reason="Internal server error")


@docs(
    tags=["pqcrypto_fm"],
    summary="Get PQC wallet information"
)
@response_schema(PQCWalletInfoResponseSchema(), 200, description="PQC wallet information")
@tenant_authentication
async def get_pqc_wallet_info(request: web.BaseRequest):
    """Get information about a PQC wallet.

    Args:
        request: aiohttp request object

    Returns:
        JSON response with wallet information
    """
    context: AdminRequestContext = request["context"]
    wallet_id = request.match_info["wallet_id"]

    try:
        wallet_service = await get_askar_wallet_service(context)
        wallet_info = await wallet_service.get_pqc_wallet_info(context.profile, wallet_id)

        return web.json_response(wallet_info)

    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"Wallet not found: {wallet_id}")
    except WalletError as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(
    tags=["pqcrypto_fm"],
    summary="List PQC wallets"
)
@response_schema(PQCWalletInfoResponseSchema(many=True), 200, description="List of PQC wallets")
@tenant_authentication
async def list_pqc_wallets(request: web.BaseRequest):
    """List all PQC-enabled wallets.

    Args:
        request: aiohttp request object

    Returns:
        JSON response with list of PQC wallets
    """
    context: AdminRequestContext = request["context"]

    try:
        wallet_service = await get_askar_wallet_service(context)
        wallets = await wallet_service.list_pqc_wallets(context.profile)

        return web.json_response({"wallets": wallets})

    except Exception as e:
        LOGGER.error(f"Error listing PQC wallets: {e}")
        raise web.HTTPInternalServerError(reason="Failed to list wallets")


async def register(app: web.Application):
    """Register routes with the application.

    Args:
        app: aiohttp application
    """
    app.add_routes([
        # Algorithm and info routes
        web.get("/pqcrypto_fm/algorithms", get_algorithms, allow_head=False),

        # Key management routes
        web.post("/pqcrypto_fm/keys", create_key),
        web.get("/pqcrypto_fm/keys", list_keys, allow_head=False),
        web.delete("/pqcrypto_fm/keys/{verkey}", delete_key),

        # Signing and verification routes
        web.post("/pqcrypto_fm/sign", sign_message),
        web.post("/pqcrypto_fm/verify", verify_signature),

        # DID management routes
        web.post("/pqcrypto_fm/dids", create_did),
        web.get("/pqcrypto_fm/dids", list_dids, allow_head=False),
        web.get("/pqcrypto_fm/dids/{did}", get_did, allow_head=False),
        web.get("/pqcrypto_fm/dids/{did}/document", get_did_document, allow_head=False),
        web.delete("/pqcrypto_fm/dids/{did}", delete_did),

        # PQC Askar Wallet management routes
        web.post("/pqcrypto_fm/wallets", create_pqc_wallet),
        web.get("/pqcrypto_fm/wallets", list_pqc_wallets, allow_head=False),
        web.get("/pqcrypto_fm/wallets/{wallet_id}", get_pqc_wallet_info, allow_head=False),
    ])


def post_process_routes(app: web.Application):
    """Post-process routes for OpenAPI documentation.

    Args:
        app: aiohttp application
    """
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []

    app._state["swagger_dict"]["tags"].append({
        "name": "pqcrypto_fm",
        "description": "Post-Quantum Cryptography operations",
        "externalDocs": {
            "description": "PQCrypto_FM Plugin Documentation",
            "url": "https://github.com/openwallet-foundation/acapy-plugins"
        }
    })
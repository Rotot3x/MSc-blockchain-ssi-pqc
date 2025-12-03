"""Patch for /wallet/did/create to support PQC did:peer:4 creation.

This module patches the wallet_create_did endpoint handler to transparently
create PQC did:peer:4 DIDs when method="peer" or method="peer:4" is requested.

NO API changes needed - existing workflows continue to work!
"""

import logging
from typing import Optional

from aiohttp import web
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo

from .pqc_peer4_creator import create_pqc_peer4_did


LOGGER = logging.getLogger(__name__)

# Store original handler for fallback
_original_wallet_create_did = None


async def wallet_create_did_pqc(request: web.BaseRequest):
    """Patched wallet_create_did handler with PQC support.

    This handler intercepts POST /wallet/did/create requests:
    - If method is "peer" or "peer:4": Create PQC did:peer:4 with ML-DSA-65 + ML-KEM-768
    - Otherwise: Fall back to original handler

    Args:
        request: aiohttp web request

    Returns:
        JSON response with DID information
    """
    context = request["context"]  # Kommt vom setup_context middleware
    body = await request.json()

    method = body.get("method")
    options = body.get("options", {})

    # Check if this is a did:peer:4 request
    if method in ["peer", "peer:4"]:
        LOGGER.info(f"PQC Patch: Intercepted /wallet/did/create with method={method}")

        try:
            # Get wallet from context
            async with context.session() as session:
                wallet = session.inject(BaseWallet)

                # Extract options
                metadata = options.get("metadata", {})

                # Get service endpoints from agent config
                # Note: /wallet/did/create doesn't receive svc_endpoints,
                # so we use the agent's configured endpoint
                agent_endpoint = context.settings.get("default_endpoint")
                svc_endpoints = [agent_endpoint] if agent_endpoint else None

                LOGGER.debug(f"  Creating PQC did:peer:4 with endpoints: {svc_endpoints}")

                # Create PQC did:peer:4
                did_info: DIDInfo = await create_pqc_peer4_did(
                    wallet=wallet,
                    svc_endpoints=svc_endpoints,
                    routing_keys=None,
                    metadata=metadata,
                )

                LOGGER.info(f"  ✅ Created PQC did:peer:4: {did_info.did[:30]}...")
                LOGGER.debug(f"     key_type: {did_info.key_type}")
                LOGGER.debug(f"     metadata: {did_info.metadata}")

                # Format response (compatible with original /wallet/did/create)
                result = {
                    "did": did_info.did,
                    "verkey": did_info.verkey,
                    "posture": "wallet_only",
                }

                # Add method and key_type if available
                if did_info.method:
                    result["method"] = did_info.method.method_name
                if did_info.key_type:
                    # Convert KeyType object to string for JSON serialization
                    result["key_type"] = did_info.key_type.key_type
                if did_info.metadata:
                    result["metadata"] = did_info.metadata

                return web.json_response({"result": result})

        except Exception as e:
            LOGGER.error(f"  ❌ Failed to create PQC did:peer:4: {e}", exc_info=True)
            raise web.HTTPBadRequest(reason=f"Failed to create PQC did:peer:4: {str(e)}")

    # Fall back to original handler for other DID methods
    LOGGER.debug(f"Falling back to original handler for method={method}")
    return await _original_wallet_create_did(request)


def patch_wallet_routes():
    """Patch the /wallet/did/create endpoint for PQC support.

    This function:
    1. Imports the wallet routes module
    2. Saves the original handler
    3. Copies decorator attributes to preserve Swagger UI documentation
    4. Replaces it with the PQC-aware handler
    """
    global _original_wallet_create_did

    try:
        # Import wallet routes module
        from acapy_agent.wallet import routes as wallet_routes
        import functools

        # Save original handler
        _original_wallet_create_did = wallet_routes.wallet_create_did

        # Copy decorator attributes from original to PQC handler
        # This preserves @docs, @request_schema, @response_schema decorators
        # so the endpoint still appears in Swagger UI
        functools.update_wrapper(
            wallet_create_did_pqc,
            _original_wallet_create_did,
            assigned=functools.WRAPPER_ASSIGNMENTS + ('__annotations__',),
            updated=functools.WRAPPER_UPDATES
        )

        # Copy any additional attributes that decorators might have set
        for attr in dir(_original_wallet_create_did):
            if not attr.startswith('_') and not callable(getattr(_original_wallet_create_did, attr)):
                try:
                    setattr(wallet_create_did_pqc, attr, getattr(_original_wallet_create_did, attr))
                except (AttributeError, TypeError):
                    pass  # Skip read-only attributes

        # Replace with PQC-aware handler
        wallet_routes.wallet_create_did = wallet_create_did_pqc

        LOGGER.info("✅ Successfully patched wallet_routes.wallet_create_did for PQC support")
        LOGGER.debug("   Swagger UI decorators preserved via functools.update_wrapper")

    except Exception as e:
        LOGGER.error(f"❌ Failed to patch wallet_routes.wallet_create_did: {e}", exc_info=True)
        raise

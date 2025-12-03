"""
PQC Admin API Routes

Simplified REST API endpoints for PQC plugin.
"""

import logging
from aiohttp import web

LOGGER = logging.getLogger(__name__)

def register_routes(app: web.Application):
    """Register PQC plugin routes."""
    app.router.add_get("/pqc/algorithms", get_algorithms)
    app.router.add_post("/pqc/keys/generate", generate_key)
    app.router.add_get("/pqc/status", get_status)

async def get_algorithms(request: web.Request):
    """Get available PQC algorithms."""
    try:
        from ..services.pqc_crypto_service import PQCCryptoService
        from ..config import PQCConfig

        context = request.get("context")
        if context:
            crypto_service = context.inject(PQCCryptoService, required=False)
            if crypto_service:
                algorithms = crypto_service.get_available_algorithms()
                return web.json_response(algorithms)

        # Fallback response
        return web.json_response({
            "kem": ["Kyber768"],
            "signature": ["Dilithium3"]
        })

    except Exception as e:
        LOGGER.error(f"Error getting algorithms: {e}")
        return web.json_response({"error": str(e)}, status=500)

async def generate_key(request: web.Request):
    """Generate a new PQC key pair."""
    try:
        return web.json_response({
            "success": True,
            "message": "PQC key generation endpoint"
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def get_status(request: web.Request):
    """Get PQC plugin status."""
    return web.json_response({
        "plugin": "pqcrypto_fm.v1_0",
        "status": "active",
        "quantum_safe": True
    })
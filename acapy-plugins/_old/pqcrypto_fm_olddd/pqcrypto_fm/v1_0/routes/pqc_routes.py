"""
PQC Admin API Routes

REST API endpoints for PQC plugin administration.
"""

import logging
from typing import Dict, Any, Optional
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema, match_info_schema
from marshmallow import fields, Schema

from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError

from ..models.pqc_key_record import PQCKeyRecord, PQCKeyRecordSchema
from ..services.pqc_key_service import PQCKeyService
from ..services.pqc_crypto_service import PQCCryptoService
from ..config import PQCConfig

LOGGER = logging.getLogger(__name__)

class PQCKeyGenerateRequestSchema(OpenAPISchema):
    """Schema for PQC key generation request."""
    
    key_type = fields.Str(
        required=True,
        description="Type of key to generate",
        validate=lambda x: x in ["kem", "sig", "hybrid"]
    )
    algorithm = fields.Str(
        required=False,
        description="Algorithm name (uses default if not specified)"
    )
    key_id = fields.Str(
        required=False,
        description="Optional key identifier"
    )
    metadata = fields.Dict(
        required=False, 
        description="Optional metadata"
    )

class PQCKeyResponseSchema(PQCKeyRecordSchema):
    """Schema for PQC key response (without private key)."""
    
    class Meta:
        exclude = ["private_key"]

class PQCAlgorithmsResponseSchema(OpenAPISchema):
    """Schema for available algorithms response."""
    
    kem = fields.List(fields.Str(), description="Available KEM algorithms")
    signature = fields.List(fields.Str(), description="Available signature algorithms")
    enabled_kem = fields.List(fields.Str(), description="Enabled KEM algorithms")
    enabled_sig = fields.List(fields.Str(), description="Enabled signature algorithms")

class PQCStatsResponseSchema(OpenAPISchema):
    """Schema for PQC key statistics."""
    
    total_keys = fields.Int(description="Total number of PQC keys")
    by_type = fields.Dict(description="Keys grouped by type")
    by_algorithm = fields.Dict(description="Keys grouped by algorithm") 
    hybrid_pairs = fields.Int(description="Number of hybrid key pairs")

def register_routes(app: web.Application):
    """Register PQC plugin routes."""
    
    app.router.add_get("/pqc/algorithms", get_algorithms, allow_head=False)
    app.router.add_post("/pqc/keys/generate", generate_key)
    app.router.add_get("/pqc/keys", list_keys, allow_head=False)
    app.router.add_get("/pqc/keys/{key_id}", get_key, allow_head=False)
    app.router.add_delete("/pqc/keys/{key_id}", delete_key)
    app.router.add_post("/pqc/keys/{key_id}/set-default", set_default_key)
    app.router.add_get("/pqc/stats", get_stats, allow_head=False)
    app.router.add_post("/pqc/test/encrypt", test_encrypt)
    app.router.add_post("/pqc/test/sign", test_sign)

@docs(
    tags=["pqc"],
    summary="Get available PQC algorithms"
)
@response_schema(PQCAlgorithmsResponseSchema, 200)
async def get_algorithms(request: web.Request):
    """Get list of available PQC algorithms."""
    context: AdminRequestContext = request["context"]
    
    try:
        crypto_service = context.inject(PQCCryptoService)
        algorithms = crypto_service.get_available_algorithms()
        
        return web.json_response(algorithms)
        
    except Exception as e:
        LOGGER.error(f"Error getting algorithms: {e}")
        return web.json_response(
            {"error": f"Failed to retrieve algorithms: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Generate new PQC key pair"
)
@request_schema(PQCKeyGenerateRequestSchema)
@response_schema(PQCKeyResponseSchema, 200)
async def generate_key(request: web.Request):
    """Generate a new PQC key pair."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    
    try:
        key_service = context.inject(PQCKeyService)
        
        key_type = body["key_type"]
        algorithm = body.get("algorithm")
        key_id = body.get("key_id")
        metadata = body.get("metadata", {})
        
        async with context.session() as session:
            if key_type == "hybrid":
                # Generate hybrid key pair
                config = context.inject(PQCConfig)
                algorithm = algorithm or config.default_kem_algorithm
                
                key_pairs = await key_service.create_hybrid_key_pair(
                    session, algorithm, key_id
                )
                
                return web.json_response({
                    "pqc_key": key_pairs["pqc"].to_dict(),
                    "classical_key": key_pairs["classical"].to_dict()
                })
            else:
                # Generate single key pair
                key_record = await key_service.create_key_pair(
                    session, key_type, algorithm, key_id, metadata
                )
                
                return web.json_response(key_record.to_dict())
                
    except ValueError as e:
        return web.json_response(
            {"error": f"Invalid request: {str(e)}"},
            status=400
        )
    except Exception as e:
        LOGGER.error(f"Error generating key: {e}")
        return web.json_response(
            {"error": f"Failed to generate key: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="List PQC keys"
)
@response_schema(PQCKeyResponseSchema(many=True), 200)
async def list_keys(request: web.Request):
    """List stored PQC keys."""
    context: AdminRequestContext = request["context"]
    
    # Query parameters
    key_type = request.query.get("key_type")
    algorithm = request.query.get("algorithm")
    
    try:
        key_service = context.inject(PQCKeyService)
        
        async with context.session() as session:
            key_records = await key_service.find_key_records(
                session, key_type=key_type, algorithm=algorithm
            )
            
            return web.json_response([
                key_record.to_dict() for key_record in key_records
            ])
            
    except Exception as e:
        LOGGER.error(f"Error listing keys: {e}")
        return web.json_response(
            {"error": f"Failed to list keys: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Get PQC key by ID"
)
@response_schema(PQCKeyResponseSchema, 200)
async def get_key(request: web.Request):
    """Get a specific PQC key by ID."""
    context: AdminRequestContext = request["context"]
    key_id = request.match_info["key_id"]
    
    try:
        key_service = context.inject(PQCKeyService)
        
        async with context.session() as session:
            key_record = await key_service.get_key_record(session, key_id)
            
            if not key_record:
                return web.json_response(
                    {"error": f"Key {key_id} not found"},
                    status=404
                )
            
            return web.json_response(key_record.to_dict())
            
    except Exception as e:
        LOGGER.error(f"Error getting key {key_id}: {e}")
        return web.json_response(
            {"error": f"Failed to get key: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Delete PQC key"
)
async def delete_key(request: web.Request):
    """Delete a PQC key."""
    context: AdminRequestContext = request["context"]
    key_id = request.match_info["key_id"]
    
    try:
        key_service = context.inject(PQCKeyService)
        
        async with context.session() as session:
            deleted = await key_service.delete_key_record(session, key_id)
            
            if not deleted:
                return web.json_response(
                    {"error": f"Key {key_id} not found"},
                    status=404
                )
            
            return web.json_response({"success": True})
            
    except Exception as e:
        LOGGER.error(f"Error deleting key {key_id}: {e}")
        return web.json_response(
            {"error": f"Failed to delete key: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Set key as default"
)
async def set_default_key(request: web.Request):
    """Set a key as the default for its type/algorithm."""
    context: AdminRequestContext = request["context"]
    key_id = request.match_info["key_id"]
    
    try:
        key_service = context.inject(PQCKeyService)
        
        async with context.session() as session:
            success = await key_service.set_default_key(session, key_id)
            
            if not success:
                return web.json_response(
                    {"error": f"Key {key_id} not found"},
                    status=404
                )
            
            return web.json_response({"success": True})
            
    except Exception as e:
        LOGGER.error(f"Error setting default key {key_id}: {e}")
        return web.json_response(
            {"error": f"Failed to set default key: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Get PQC key statistics"
)
@response_schema(PQCStatsResponseSchema, 200)
async def get_stats(request: web.Request):
    """Get PQC key usage statistics."""
    context: AdminRequestContext = request["context"]
    
    try:
        key_service = context.inject(PQCKeyService)
        
        async with context.session() as session:
            stats = await key_service.get_key_statistics(session)
            
            return web.json_response(stats)
            
    except Exception as e:
        LOGGER.error(f"Error getting stats: {e}")
        return web.json_response(
            {"error": f"Failed to get statistics: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Test PQC encryption"
)
async def test_encrypt(request: web.Request):
    """Test PQC encryption/decryption."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    
    try:
        crypto_service = context.inject(PQCCryptoService)
        key_service = context.inject(PQCKeyService)
        
        message = body.get("message", "Hello, PQC World!").encode()
        algorithm = body.get("algorithm", "Kyber768")
        
        async with context.session() as session:
            # Find or create test key
            keys = await key_service.find_key_records(
                session, key_type="kem", algorithm=algorithm
            )
            
            if not keys:
                key_record = await key_service.create_key_pair(
                    session, "kem", algorithm, f"test_{algorithm}"
                )
            else:
                key_record = keys[0]
            
            # Test encryption
            ciphertext, shared_secret = crypto_service.kem_encapsulate(
                key_record.public_key, algorithm
            )
            
            # Test decryption  
            decrypted_secret = crypto_service.kem_decapsulate(
                ciphertext, key_record.private_key, algorithm
            )
            
            success = shared_secret == decrypted_secret
            
            return web.json_response({
                "success": success,
                "algorithm": algorithm,
                "message_length": len(message),
                "ciphertext_length": len(ciphertext),
                "shared_secret_length": len(shared_secret)
            })
            
    except Exception as e:
        LOGGER.error(f"Error in encryption test: {e}")
        return web.json_response(
            {"error": f"Encryption test failed: {str(e)}"},
            status=500
        )

@docs(
    tags=["pqc"],
    summary="Test PQC signing"
)
async def test_sign(request: web.Request):
    """Test PQC signing/verification."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    
    try:
        crypto_service = context.inject(PQCCryptoService)
        key_service = context.inject(PQCKeyService)
        
        message = body.get("message", "Hello, PQC World!").encode()
        algorithm = body.get("algorithm", "Dilithium3")
        
        async with context.session() as session:
            # Find or create test key
            keys = await key_service.find_key_records(
                session, key_type="sig", algorithm=algorithm
            )
            
            if not keys:
                key_record = await key_service.create_key_pair(
                    session, "sig", algorithm, f"test_{algorithm}"
                )
            else:
                key_record = keys[0]
            
            # Test signing
            signature = crypto_service.sign_message(
                message, key_record.private_key, algorithm
            )
            
            # Test verification
            valid = crypto_service.verify_signature(
                message, signature, key_record.public_key, algorithm
            )
            
            return web.json_response({
                "success": valid,
                "algorithm": algorithm,
                "message_length": len(message),
                "signature_length": len(signature)
            })
            
    except Exception as e:
        LOGGER.error(f"Error in signing test: {e}")
        return web.json_response(
            {"error": f"Signing test failed: {str(e)}"},
            status=500
        )
"""
PQC Key Management Service

Simplified key management for PQC keys.
"""

import logging
from typing import Optional, List

LOGGER = logging.getLogger(__name__)

class PQCKeyService:
    """Service for managing PQC keys."""

    def __init__(self, crypto_service):
        self.crypto_service = crypto_service

    async def create_key_pair(self, session, key_type: str, algorithm: str):
        """Create and store a new PQC key pair."""
        LOGGER.debug(f"Creating {key_type} key pair with {algorithm}")

        if key_type == "kem":
            key_pair = self.crypto_service.generate_kem_keypair(algorithm)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        LOGGER.info(f"✅ Created {key_type} key pair with {algorithm}")
        return key_pair
"""
PQC Key Management Service

Service for managing PQC keys in ACA-Py wallet storage.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from aries_cloudagent.core.profile import ProfileSession
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.wallet.base import BaseWallet

from .pqc_crypto_service import PQCCryptoService, PQCKeyPair
from ..models.pqc_key_record import PQCKeyRecord

LOGGER = logging.getLogger(__name__)

class PQCKeyService:
    """
    Service for managing PQC keys in ACA-Py storage.
    """
    
    RECORD_TYPE_PQC_KEY = "pqc_key"
    
    def __init__(self, crypto_service: PQCCryptoService):
        """
        Initialize PQC key service.
        
        Args:
            crypto_service: PQC cryptographic service
        """
        self.crypto_service = crypto_service
    
    async def create_key_pair(self, session: ProfileSession, 
                            key_type: str, algorithm: str,
                            key_id: Optional[str] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> PQCKeyRecord:
        """
        Create and store a new PQC key pair.
        
        Args:
            session: Profile session for storage access
            key_type: Type of key ('kem', 'sig', 'hash_sig')
            algorithm: PQC algorithm name
            key_id: Optional key identifier
            metadata: Optional metadata
            
        Returns:
            Created PQC key record
            
        Raises:
            ValueError: If key type or algorithm not supported
        """
        LOGGER.debug(f"Creating {key_type} key pair with {algorithm}")
        
        # Generate key pair based on type
        if key_type == "kem":
            key_pair = self.crypto_service.generate_kem_keypair(algorithm)
        elif key_type == "sig":
            key_pair = self.crypto_service.generate_sig_keypair(algorithm)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Create key record
        key_record = PQCKeyRecord(
            key_id=key_id,
            key_type=key_type,
            algorithm=algorithm,
            public_key=key_pair.public_key,
            private_key=key_pair.private_key,
            created_at=datetime.now(timezone.utc),
            metadata=metadata or {}
        )
        
        # Store in wallet
        await self._store_key_record(session, key_record)
        
        LOGGER.info(f"✅ Created {key_type} key pair {key_record.record_id} with {algorithm}")
        
        return key_record
    
    async def get_key_record(self, session: ProfileSession, 
                           record_id: str) -> Optional[PQCKeyRecord]:
        """
        Retrieve a PQC key record by ID.
        
        Args:
            session: Profile session
            record_id: Key record ID
            
        Returns:
            PQC key record if found, None otherwise
        """
        try:
            storage = session.inject(BaseStorage)
            record = await storage.get_record(
                self.RECORD_TYPE_PQC_KEY, 
                record_id
            )
            return PQCKeyRecord.from_storage_record(record)
        except Exception as e:
            LOGGER.debug(f"Key record {record_id} not found: {e}")
            return None
    
    async def find_key_records(self, session: ProfileSession,
                             key_type: Optional[str] = None,
                             algorithm: Optional[str] = None,
                             tag_filter: Optional[Dict[str, str]] = None) -> List[PQCKeyRecord]:
        """
        Find PQC key records matching criteria.
        
        Args:
            session: Profile session
            key_type: Filter by key type
            algorithm: Filter by algorithm
            tag_filter: Additional tag filters
            
        Returns:
            List of matching key records
        """
        storage = session.inject(BaseStorage)
        
        # Build tag filter
        tags = tag_filter or {}
        if key_type:
            tags["key_type"] = key_type
        if algorithm:
            tags["algorithm"] = algorithm
        
        records = await storage.find_all_records(
            self.RECORD_TYPE_PQC_KEY,
            tag_filter=tags
        )
        
        return [PQCKeyRecord.from_storage_record(record) for record in records]
    
    async def delete_key_record(self, session: ProfileSession, 
                              record_id: str) -> bool:
        """
        Delete a PQC key record.
        
        Args:
            session: Profile session
            record_id: Key record ID
            
        Returns:
            True if deleted, False if not found
        """
        try:
            storage = session.inject(BaseStorage)
            await storage.delete_record(
                self.RECORD_TYPE_PQC_KEY,
                record_id
            )
            LOGGER.info(f"🗑️  Deleted PQC key record {record_id}")
            return True
        except Exception as e:
            LOGGER.debug(f"Failed to delete key record {record_id}: {e}")
            return False
    
    async def update_key_metadata(self, session: ProfileSession,
                                record_id: str, 
                                metadata: Dict[str, Any]) -> Optional[PQCKeyRecord]:
        """
        Update key record metadata.
        
        Args:
            session: Profile session
            record_id: Key record ID
            metadata: New metadata
            
        Returns:
            Updated key record if successful
        """
        key_record = await self.get_key_record(session, record_id)
        if not key_record:
            return None
        
        # Update metadata
        key_record.metadata.update(metadata)
        key_record.updated_at = datetime.now(timezone.utc)
        
        # Store updated record
        await self._store_key_record(session, key_record)
        
        return key_record
    
    async def create_hybrid_key_pair(self, session: ProfileSession,
                                   pqc_algorithm: str,
                                   key_id: Optional[str] = None) -> Dict[str, PQCKeyRecord]:
        """
        Create hybrid key pair (PQC + Classical).
        
        Args:
            session: Profile session
            pqc_algorithm: PQC KEM algorithm
            key_id: Optional key identifier base
            
        Returns:
            Dictionary with 'pqc' and 'classical' key records
        """
        # Create PQC KEM key pair
        pqc_key = await self.create_key_pair(
            session, "kem", pqc_algorithm, 
            key_id=f"{key_id}_pqc" if key_id else None,
            metadata={"hybrid": True, "role": "pqc"}
        )
        
        # Create classical key pair
        classical_pub, classical_priv = self.crypto_service.generate_classical_keypair()
        
        classical_key = PQCKeyRecord(
            key_id=f"{key_id}_classical" if key_id else None,
            key_type="classical_ecdh",
            algorithm="ECDH-P256",
            public_key=classical_pub,
            private_key=classical_priv,
            created_at=datetime.now(timezone.utc),
            metadata={"hybrid": True, "role": "classical", "paired_with": pqc_key.record_id}
        )
        
        await self._store_key_record(session, classical_key)
        
        # Update PQC key with pairing info
        await self.update_key_metadata(
            session, pqc_key.record_id,
            {"paired_with": classical_key.record_id}
        )
        
        LOGGER.info(f"✅ Created hybrid key pair: PQC({pqc_key.record_id}) + Classical({classical_key.record_id})")
        
        return {
            "pqc": pqc_key,
            "classical": classical_key
        }
    
    async def get_default_key_for_algorithm(self, session: ProfileSession,
                                          key_type: str, 
                                          algorithm: str) -> Optional[PQCKeyRecord]:
        """
        Get default key for specified algorithm.
        
        Args:
            session: Profile session
            key_type: Key type ('kem', 'sig')
            algorithm: Algorithm name
            
        Returns:
            Default key record if found
        """
        records = await self.find_key_records(
            session, key_type=key_type, algorithm=algorithm,
            tag_filter={"default": "true"}
        )
        
        if records:
            return records[0]
        
        # If no default found, return any key of that type/algorithm
        records = await self.find_key_records(
            session, key_type=key_type, algorithm=algorithm
        )
        
        return records[0] if records else None
    
    async def set_default_key(self, session: ProfileSession, 
                            record_id: str) -> bool:
        """
        Set a key as the default for its type/algorithm.
        
        Args:
            session: Profile session
            record_id: Key record ID to set as default
            
        Returns:
            True if successful
        """
        key_record = await self.get_key_record(session, record_id)
        if not key_record:
            return False
        
        # Remove default flag from other keys of same type/algorithm
        existing_defaults = await self.find_key_records(
            session, 
            key_type=key_record.key_type,
            algorithm=key_record.algorithm,
            tag_filter={"default": "true"}
        )
        
        for default_key in existing_defaults:
            if default_key.record_id != record_id:
                await self.update_key_metadata(
                    session, default_key.record_id,
                    {"default": "false"}
                )
        
        # Set this key as default
        await self.update_key_metadata(
            session, record_id,
            {"default": "true"}
        )
        
        LOGGER.info(f"✅ Set key {record_id} as default for {key_record.key_type}/{key_record.algorithm}")
        
        return True
    
    async def _store_key_record(self, session: ProfileSession, 
                              key_record: PQCKeyRecord) -> None:
        """
        Store PQC key record in wallet storage.
        
        Args:
            session: Profile session
            key_record: Key record to store
        """
        storage = session.inject(BaseStorage)
        
        record = StorageRecord(
            type=self.RECORD_TYPE_PQC_KEY,
            id=key_record.record_id,
            value=key_record.to_json(),
            tags=key_record.get_tags()
        )
        
        if await self.get_key_record(session, key_record.record_id):
            # Update existing record
            await storage.update_record(record, record.value, record.tags)
        else:
            # Create new record
            await storage.add_record(record)
    
    async def get_key_statistics(self, session: ProfileSession) -> Dict[str, Any]:
        """
        Get statistics about stored PQC keys.
        
        Args:
            session: Profile session
            
        Returns:
            Key statistics
        """
        all_keys = await self.find_key_records(session)
        
        stats = {
            "total_keys": len(all_keys),
            "by_type": {},
            "by_algorithm": {},
            "hybrid_pairs": 0
        }
        
        for key in all_keys:
            # Count by type
            stats["by_type"][key.key_type] = stats["by_type"].get(key.key_type, 0) + 1
            
            # Count by algorithm
            stats["by_algorithm"][key.algorithm] = stats["by_algorithm"].get(key.algorithm, 0) + 1
            
            # Count hybrid pairs
            if key.metadata.get("hybrid"):
                stats["hybrid_pairs"] += 1
        
        # Hybrid pairs are counted twice (PQC + classical), so divide by 2
        stats["hybrid_pairs"] = stats["hybrid_pairs"] // 2
        
        return stats
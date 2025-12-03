"""
PQC Key Record Model

Data model for storing PQC keys in ACA-Py wallet.
"""

import json
import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from marshmallow import Schema, fields, post_load

from aries_cloudagent.storage.record import StorageRecord

@dataclass
class PQCKeyRecord:
    """
    Record for storing PQC key pairs in ACA-Py wallet.
    """
    
    # Core fields
    key_type: str  # 'kem', 'sig', 'hash_sig', 'classical_ecdh'
    algorithm: str
    public_key: bytes
    private_key: bytes
    
    # Metadata
    record_id: str = None
    key_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.record_id is None:
            self.record_id = str(uuid.uuid4())
        
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
            
        if self.metadata is None:
            self.metadata = {}
    
    @classmethod
    def from_storage_record(cls, record: StorageRecord) -> "PQCKeyRecord":
        """
        Create PQCKeyRecord from storage record.
        
        Args:
            record: Storage record from wallet
            
        Returns:
            PQCKeyRecord instance
        """
        data = json.loads(record.value)
        
        return cls(
            record_id=record.id,
            key_type=data["key_type"],
            algorithm=data["algorithm"],
            public_key=bytes.fromhex(data["public_key"]),
            private_key=bytes.fromhex(data["private_key"]),
            key_id=data.get("key_id"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            metadata=data.get("metadata", {})
        )
    
    def to_json(self) -> str:
        """
        Serialize key record to JSON for storage.
        
        Returns:
            JSON string representation
        """
        data = {
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "public_key": self.public_key.hex(),
            "private_key": self.private_key.hex(),
            "key_id": self.key_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "metadata": self.metadata
        }
        
        return json.dumps(data)
    
    def get_tags(self) -> Dict[str, str]:
        """
        Get storage tags for indexing.
        
        Returns:
            Dictionary of storage tags
        """
        tags = {
            "key_type": self.key_type,
            "algorithm": self.algorithm
        }
        
        if self.key_id:
            tags["key_id"] = self.key_id
        
        # Add metadata tags
        for key, value in self.metadata.items():
            if isinstance(value, (str, int, bool)):
                tags[f"meta_{key}"] = str(value)
        
        return tags
    
    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary for API responses.
        
        Args:
            include_private: Whether to include private key
            
        Returns:
            Dictionary representation
        """
        result = {
            "record_id": self.record_id,
            "key_id": self.key_id,
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "public_key": self.public_key.hex(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "metadata": self.metadata
        }
        
        if include_private:
            result["private_key"] = self.private_key.hex()
        
        return result

class PQCKeyRecordSchema(Schema):
    """Marshmallow schema for PQC key records."""
    
    record_id = fields.Str(required=True)
    key_id = fields.Str(required=False, allow_none=True)
    key_type = fields.Str(required=True)
    algorithm = fields.Str(required=True)
    public_key = fields.Str(required=True)  # hex encoded
    private_key = fields.Str(required=False)  # hex encoded, optional in responses
    created_at = fields.DateTime(required=False, allow_none=True)
    updated_at = fields.DateTime(required=False, allow_none=True)
    metadata = fields.Dict(required=False, missing=dict)
    
    @post_load
    def make_record(self, data, **kwargs):
        """Convert schema data to PQCKeyRecord."""
        if "public_key" in data:
            data["public_key"] = bytes.fromhex(data["public_key"])
        if "private_key" in data:
            data["private_key"] = bytes.fromhex(data["private_key"])
        
        return PQCKeyRecord(**data)
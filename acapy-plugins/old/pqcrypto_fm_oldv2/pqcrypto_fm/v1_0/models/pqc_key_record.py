"""
PQC Key Record Model

Simplified data model for PQC keys.
"""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime

@dataclass 
class PQCKeyRecord:
    """Record for storing PQC key pairs."""

    key_type: str
    algorithm: str
    public_key: bytes
    private_key: bytes
    record_id: str = None

    def __post_init__(self):
        if self.record_id is None:
            self.record_id = str(uuid.uuid4())

    def to_dict(self, include_private: bool = False):
        """Convert to dictionary for API responses."""
        result = {
            "record_id": self.record_id,
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "public_key": self.public_key.hex(),
        }

        if include_private:
            result["private_key"] = self.private_key.hex()

        return result
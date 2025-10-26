"""PQC Schema and Credential Definition models."""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class PQCSchema:
    """Post-Quantum Cryptography Schema."""

    id: str
    name: str
    version: str
    issuer_did: str
    attributes: List[str]
    pqc_algorithm_suite: Dict[str, str]
    created: str
    signature: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "issuerDid": self.issuer_did,
            "attributes": self.attributes,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "created": self.created
        }

        if self.signature:
            result["signature"] = self.signature

        return result

    def to_dict_for_signing(self) -> Dict[str, Any]:
        """Convert to dictionary for signing (without signature field)."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "issuerDid": self.issuer_did,
            "attributes": self.attributes,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "created": self.created
        }

    def add_signature(self, signature: Dict[str, Any]):
        """Add signature to schema."""
        self.signature = signature

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCSchema':
        """Create schema from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            issuer_did=data["issuerDid"],
            attributes=data["attributes"],
            pqc_algorithm_suite=data["pqcAlgorithmSuite"],
            created=data["created"],
            signature=data.get("signature")
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCSchema':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> List[str]:
        """Validate schema structure.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        if not self.id:
            errors.append("Schema must have an 'id' field")

        if not self.name:
            errors.append("Schema must have a 'name' field")

        if not self.version:
            errors.append("Schema must have a 'version' field")

        if not self.issuer_did:
            errors.append("Schema must have an 'issuerDid' field")

        if not self.attributes:
            errors.append("Schema must have at least one attribute")

        # Validate attributes
        if self.attributes:
            for attr in self.attributes:
                if not isinstance(attr, str) or not attr.strip():
                    errors.append(f"Invalid attribute: {attr}")

        # Validate DID format
        if self.issuer_did and not self.issuer_did.startswith("did:"):
            errors.append("issuerDid must be a valid DID")

        # Validate algorithm suite
        if self.pqc_algorithm_suite:
            required_algs = ["signature", "keyEncapsulation"]
            for alg in required_algs:
                if alg not in self.pqc_algorithm_suite:
                    errors.append(f"Missing algorithm: {alg}")

        return errors

    def is_valid(self) -> bool:
        """Check if schema is valid."""
        return len(self.validate()) == 0


@dataclass
class PQCCredentialDefinition:
    """Post-Quantum Cryptography Credential Definition."""

    id: str
    schema_id: str
    issuer_did: str
    tag: str
    pqc_keys: Dict[str, Any]
    pqc_algorithm_suite: Dict[str, str]
    support_revocation: bool
    created: str
    revocation_registry_id: Optional[str] = None
    signature: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "schemaId": self.schema_id,
            "issuerDid": self.issuer_did,
            "tag": self.tag,
            "pqcKeys": self.pqc_keys,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "supportRevocation": self.support_revocation,
            "created": self.created
        }

        if self.revocation_registry_id:
            result["revocationRegistryId"] = self.revocation_registry_id

        if self.signature:
            result["signature"] = self.signature

        return result

    def to_dict_for_signing(self) -> Dict[str, Any]:
        """Convert to dictionary for signing (without signature field)."""
        result = {
            "id": self.id,
            "schemaId": self.schema_id,
            "issuerDid": self.issuer_did,
            "tag": self.tag,
            "pqcKeys": self.pqc_keys,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "supportRevocation": self.support_revocation,
            "created": self.created
        }

        if self.revocation_registry_id:
            result["revocationRegistryId"] = self.revocation_registry_id

        return result

    def add_signature(self, signature: Dict[str, Any]):
        """Add signature to credential definition."""
        self.signature = signature

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCCredentialDefinition':
        """Create credential definition from dictionary."""
        return cls(
            id=data["id"],
            schema_id=data["schemaId"],
            issuer_did=data["issuerDid"],
            tag=data["tag"],
            pqc_keys=data["pqcKeys"],
            pqc_algorithm_suite=data["pqcAlgorithmSuite"],
            support_revocation=data["supportRevocation"],
            created=data["created"],
            revocation_registry_id=data.get("revocationRegistryId"),
            signature=data.get("signature")
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCCredentialDefinition':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> List[str]:
        """Validate credential definition structure.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        if not self.id:
            errors.append("Credential definition must have an 'id' field")

        if not self.schema_id:
            errors.append("Credential definition must have a 'schemaId' field")

        if not self.issuer_did:
            errors.append("Credential definition must have an 'issuerDid' field")

        if not self.tag:
            errors.append("Credential definition must have a 'tag' field")

        if not self.pqc_keys:
            errors.append("Credential definition must have 'pqcKeys'")

        # Validate DID format
        if self.issuer_did and not self.issuer_did.startswith("did:"):
            errors.append("issuerDid must be a valid DID")

        # Validate PQC keys structure
        if self.pqc_keys:
            required_keys = ["algorithm", "masterSecret", "attributeKeys"]
            for key in required_keys:
                if key not in self.pqc_keys:
                    errors.append(f"Missing PQC key component: {key}")

        # Validate algorithm suite
        if self.pqc_algorithm_suite:
            required_algs = ["signature", "keyEncapsulation"]
            for alg in required_algs:
                if alg not in self.pqc_algorithm_suite:
                    errors.append(f"Missing algorithm: {alg}")

        return errors

    def is_valid(self) -> bool:
        """Check if credential definition is valid."""
        return len(self.validate()) == 0

    def get_attribute_keys(self) -> Dict[str, str]:
        """Get attribute keys from PQC keys."""
        return self.pqc_keys.get("attributeKeys", {})

    def supports_attribute(self, attribute: str) -> bool:
        """Check if credential definition supports an attribute."""
        attribute_keys = self.get_attribute_keys()
        return attribute in attribute_keys


@dataclass
class PQCRevocationRegistry:
    """Post-Quantum Cryptography Revocation Registry."""

    id: str
    creddef_id: str
    issuer_did: str
    type: str  # "PQC_ACCUMULATOR" or "PQC_MERKLE_TREE"
    max_credentials: int
    pqc_algorithm_suite: Dict[str, str]
    public_keys: Dict[str, Any]
    created: str
    signature: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "creddefId": self.creddef_id,
            "issuerDid": self.issuer_did,
            "type": self.type,
            "maxCredentials": self.max_credentials,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "publicKeys": self.public_keys,
            "created": self.created
        }

        if self.signature:
            result["signature"] = self.signature

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCRevocationRegistry':
        """Create revocation registry from dictionary."""
        return cls(
            id=data["id"],
            creddef_id=data["creddefId"],
            issuer_did=data["issuerDid"],
            type=data["type"],
            max_credentials=data["maxCredentials"],
            pqc_algorithm_suite=data["pqcAlgorithmSuite"],
            public_keys=data["publicKeys"],
            created=data["created"],
            signature=data.get("signature")
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCRevocationRegistry':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
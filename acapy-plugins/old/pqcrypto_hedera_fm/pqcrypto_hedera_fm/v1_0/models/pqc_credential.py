"""PQC Credential models - Post-Quantum native credentials."""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class PQCCredentialOffer:
    """Post-Quantum Cryptography Credential Offer."""

    id: str
    issuer_did: str
    creddef_id: str
    nonce: str
    pqc_algorithm_suite: Dict[str, str]
    expires_at: str
    created: str
    holder_did: Optional[str] = None
    attributes_preview: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "issuerDid": self.issuer_did,
            "creddefId": self.creddef_id,
            "nonce": self.nonce,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "expiresAt": self.expires_at,
            "created": self.created
        }

        if self.holder_did:
            result["holderDid"] = self.holder_did

        if self.attributes_preview:
            result["attributesPreview"] = self.attributes_preview

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCCredentialOffer':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            issuer_did=data["issuerDid"],
            creddef_id=data["creddefId"],
            nonce=data["nonce"],
            pqc_algorithm_suite=data["pqcAlgorithmSuite"],
            expires_at=data["expiresAt"],
            created=data["created"],
            holder_did=data.get("holderDid"),
            attributes_preview=data.get("attributesPreview")
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCCredentialOffer':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


@dataclass
class PQCCredentialRequest:
    """Post-Quantum Cryptography Credential Request."""

    id: str
    offer_id: str
    holder_did: str
    creddef_id: str
    nonce: str
    master_secret_commitment: str
    signature: Dict[str, Any]
    created: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "offerId": self.offer_id,
            "holderDid": self.holder_did,
            "creddefId": self.creddef_id,
            "nonce": self.nonce,
            "masterSecretCommitment": self.master_secret_commitment,
            "signature": self.signature,
            "created": self.created
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCCredentialRequest':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            offer_id=data["offerId"],
            holder_did=data["holderDid"],
            creddef_id=data["creddefId"],
            nonce=data["nonce"],
            master_secret_commitment=data["masterSecretCommitment"],
            signature=data["signature"],
            created=data["created"]
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCCredentialRequest':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


@dataclass
class PQCCredential:
    """Post-Quantum Cryptography Credential."""

    id: str
    schema_id: str
    creddef_id: str
    issuer_did: str
    holder_did: str
    attributes: Dict[str, str]
    credential_values: Dict[str, Any]
    proof: Dict[str, Any]
    pqc_algorithm_suite: Dict[str, str]
    issued_at: str
    expires_at: Optional[str] = None
    revocation_registry_id: Optional[str] = None
    revocation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "schemaId": self.schema_id,
            "creddefId": self.creddef_id,
            "issuerDid": self.issuer_did,
            "holderDid": self.holder_did,
            "attributes": self.attributes,
            "credentialValues": self.credential_values,
            "proof": self.proof,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "issuedAt": self.issued_at
        }

        if self.expires_at:
            result["expiresAt"] = self.expires_at

        if self.revocation_registry_id:
            result["revocationRegistryId"] = self.revocation_registry_id

        if self.revocation_id:
            result["revocationId"] = self.revocation_id

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCCredential':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            schema_id=data["schemaId"],
            creddef_id=data["creddefId"],
            issuer_did=data["issuerDid"],
            holder_did=data["holderDid"],
            attributes=data["attributes"],
            credential_values=data["credentialValues"],
            proof=data["proof"],
            pqc_algorithm_suite=data["pqcAlgorithmSuite"],
            issued_at=data["issuedAt"],
            expires_at=data.get("expiresAt"),
            revocation_registry_id=data.get("revocationRegistryId"),
            revocation_id=data.get("revocationId")
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCCredential':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> List[str]:
        """Validate credential structure.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        required_fields = [
            "id", "schema_id", "creddef_id", "issuer_did", "holder_did",
            "attributes", "credential_values", "proof", "pqc_algorithm_suite",
            "issued_at"
        ]

        for field in required_fields:
            value = getattr(self, field)
            if not value:
                errors.append(f"Missing required field: {field}")

        # Validate DIDs
        for did_field in ["issuer_did", "holder_did"]:
            did_value = getattr(self, did_field)
            if did_value and not did_value.startswith("did:"):
                errors.append(f"Invalid DID format: {did_field}")

        # Validate attributes match credential values
        if self.attributes and self.credential_values:
            for attr_name in self.attributes.keys():
                if attr_name not in self.credential_values:
                    errors.append(f"Attribute '{attr_name}' missing from credential values")

        # Validate proof structure
        if self.proof:
            required_proof_fields = ["type", "signatureValue", "algorithm"]
            for field in required_proof_fields:
                if field not in self.proof:
                    errors.append(f"Missing proof field: {field}")

        return errors

    def is_valid(self) -> bool:
        """Check if credential is valid."""
        return len(self.validate()) == 0

    def get_attribute_value(self, attribute_name: str) -> Optional[str]:
        """Get attribute value by name."""
        return self.attributes.get(attribute_name)

    def has_attribute(self, attribute_name: str) -> bool:
        """Check if credential has an attribute."""
        return attribute_name in self.attributes


@dataclass
class PQCPresentation:
    """Post-Quantum Cryptography Presentation."""

    id: str
    holder_did: str
    credentials: List[PQCCredential]
    revealed_attributes: Dict[str, Any]
    proof: Dict[str, Any]
    challenge: str
    created: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "holderDid": self.holder_did,
            "credentials": [cred.to_dict() for cred in self.credentials],
            "revealedAttributes": self.revealed_attributes,
            "proof": self.proof,
            "challenge": self.challenge,
            "created": self.created
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCPresentation':
        """Create from dictionary."""
        credentials = [
            PQCCredential.from_dict(cred_data)
            for cred_data in data["credentials"]
        ]

        return cls(
            id=data["id"],
            holder_did=data["holderDid"],
            credentials=credentials,
            revealed_attributes=data["revealedAttributes"],
            proof=data["proof"],
            challenge=data["challenge"],
            created=data["created"]
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCPresentation':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> List[str]:
        """Validate presentation structure.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        required_fields = [
            "id", "holder_did", "credentials", "revealed_attributes",
            "proof", "challenge", "created"
        ]

        for field in required_fields:
            value = getattr(self, field)
            if value is None:
                errors.append(f"Missing required field: {field}")

        # Validate holder DID
        if self.holder_did and not self.holder_did.startswith("did:"):
            errors.append("Invalid holder DID format")

        # Validate credentials
        if self.credentials:
            for i, credential in enumerate(self.credentials):
                cred_errors = credential.validate()
                for error in cred_errors:
                    errors.append(f"Credential {i}: {error}")
        else:
            errors.append("Presentation must contain at least one credential")

        # Validate proof structure
        if self.proof:
            required_proof_fields = ["type", "signatureValue", "algorithm"]
            for field in required_proof_fields:
                if field not in self.proof:
                    errors.append(f"Missing proof field: {field}")

        return errors

    def is_valid(self) -> bool:
        """Check if presentation is valid."""
        return len(self.validate()) == 0

    def get_credentials_by_schema(self, schema_id: str) -> List[PQCCredential]:
        """Get credentials by schema ID."""
        return [cred for cred in self.credentials if cred.schema_id == schema_id]

    def get_revealed_attribute(self, attr_name: str) -> Optional[Any]:
        """Get revealed attribute by name."""
        return self.revealed_attributes.get(attr_name)


@dataclass
class PQCProofRequest:
    """Post-Quantum Cryptography Proof Request."""

    id: str
    name: str
    version: str
    nonce: str
    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]
    verifier_did: str
    pqc_algorithm_suite: Dict[str, str]
    created: str
    expires_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "nonce": self.nonce,
            "requestedAttributes": self.requested_attributes,
            "requestedPredicates": self.requested_predicates,
            "verifierDid": self.verifier_did,
            "pqcAlgorithmSuite": self.pqc_algorithm_suite,
            "created": self.created
        }

        if self.expires_at:
            result["expiresAt"] = self.expires_at

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCProofRequest':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            nonce=data["nonce"],
            requested_attributes=data["requestedAttributes"],
            requested_predicates=data["requestedPredicates"],
            verifier_did=data["verifierDid"],
            pqc_algorithm_suite=data["pqcAlgorithmSuite"],
            created=data["created"],
            expires_at=data.get("expiresAt")
        )

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCProofRequest':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
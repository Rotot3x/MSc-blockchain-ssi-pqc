"""PQC DID Document models for Hedera integration."""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class PQCVerificationMethod:
    """PQC Verification Method for DID documents."""

    id: str
    type: str
    controller: str
    public_key_multibase: str
    pqc_algorithm: str
    key_encoding: str = "base64"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "controller": self.controller,
            "publicKeyMultibase": self.public_key_multibase,
            "pqcAlgorithm": self.pqc_algorithm,
            "keyEncoding": self.key_encoding
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCVerificationMethod':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            type=data["type"],
            controller=data["controller"],
            public_key_multibase=data["publicKeyMultibase"],
            pqc_algorithm=data["pqcAlgorithm"],
            key_encoding=data.get("keyEncoding", "base64")
        )


@dataclass
class PQCService:
    """Service entry for PQC DID documents."""

    id: str
    type: str
    service_endpoint: Any

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "serviceEndpoint": self.service_endpoint
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCService':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            type=data["type"],
            service_endpoint=data["serviceEndpoint"]
        )


class PQCDIDDocument:
    """Post-Quantum Cryptography DID Document."""

    def __init__(
        self,
        id: str,
        context: Optional[List[str]] = None,
        also_known_as: Optional[List[str]] = None
    ):
        """Initialize PQC DID Document.

        Args:
            id: DID identifier
            context: JSON-LD context
            also_known_as: Alternative identifiers
        """
        self.id = id
        self.context = context or [
            "https://www.w3.org/ns/did/v1",
            "https://pqc-consortium.org/contexts/pqc-v1.jsonld"
        ]
        self.also_known_as = also_known_as or []

        # DID Document components
        self.verification_method: List[PQCVerificationMethod] = []
        self.authentication: List[str] = []
        self.assertion_method: List[str] = []
        self.key_agreement: List[str] = []
        self.capability_invocation: List[str] = []
        self.capability_delegation: List[str] = []
        self.service: List[PQCService] = []

        # Metadata and proofs
        self.metadata: Dict[str, Any] = {}
        self.proof: Optional[Dict[str, Any]] = None

    def add_verification_method(self, vm: PQCVerificationMethod):
        """Add verification method."""
        # Remove existing method with same ID
        self.verification_method = [
            existing for existing in self.verification_method
            if existing.id != vm.id
        ]
        self.verification_method.append(vm)

    def remove_verification_method(self, vm_id: str):
        """Remove verification method by ID."""
        self.verification_method = [
            vm for vm in self.verification_method
            if vm.id != vm_id
        ]

    def add_authentication(self, vm_reference: str):
        """Add authentication reference."""
        if vm_reference not in self.authentication:
            self.authentication.append(vm_reference)

    def add_assertion_method(self, vm_reference: str):
        """Add assertion method reference."""
        if vm_reference not in self.assertion_method:
            self.assertion_method.append(vm_reference)

    def add_key_agreement(self, vm_reference: str):
        """Add key agreement reference."""
        if vm_reference not in self.key_agreement:
            self.key_agreement.append(vm_reference)

    def add_capability_invocation(self, vm_reference: str):
        """Add capability invocation reference."""
        if vm_reference not in self.capability_invocation:
            self.capability_invocation.append(vm_reference)

    def add_capability_delegation(self, vm_reference: str):
        """Add capability delegation reference."""
        if vm_reference not in self.capability_delegation:
            self.capability_delegation.append(vm_reference)

    def add_service(self, service: Dict[str, Any]):
        """Add service entry."""
        pqc_service = PQCService.from_dict(service)

        # Remove existing service with same ID
        self.service = [
            existing for existing in self.service
            if existing.id != pqc_service.id
        ]
        self.service.append(pqc_service)

    def remove_service(self, service_id: str):
        """Remove service by ID."""
        self.service = [
            service for service in self.service
            if service.id != service_id
        ]

    def add_metadata(self, metadata: Dict[str, Any]):
        """Add metadata to the document."""
        self.metadata.update(metadata)

    def add_proof(self, proof: Dict[str, Any]):
        """Add proof to the document."""
        self.proof = proof

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "@context": self.context,
            "id": self.id
        }

        if self.also_known_as:
            result["alsoKnownAs"] = self.also_known_as

        if self.verification_method:
            result["verificationMethod"] = [vm.to_dict() for vm in self.verification_method]

        if self.authentication:
            result["authentication"] = self.authentication

        if self.assertion_method:
            result["assertionMethod"] = self.assertion_method

        if self.key_agreement:
            result["keyAgreement"] = self.key_agreement

        if self.capability_invocation:
            result["capabilityInvocation"] = self.capability_invocation

        if self.capability_delegation:
            result["capabilityDelegation"] = self.capability_delegation

        if self.service:
            result["service"] = [service.to_dict() for service in self.service]

        # Add metadata
        if self.metadata:
            result.update(self.metadata)

        # Add proof
        if self.proof:
            result["proof"] = self.proof

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PQCDIDDocument':
        """Create PQC DID Document from dictionary."""

        # Extract core fields
        did_id = data["id"]
        context = data.get("@context", [])
        also_known_as = data.get("alsoKnownAs", [])

        # Create document
        doc = cls(id=did_id, context=context, also_known_as=also_known_as)

        # Add verification methods
        if "verificationMethod" in data:
            for vm_data in data["verificationMethod"]:
                vm = PQCVerificationMethod.from_dict(vm_data)
                doc.add_verification_method(vm)

        # Add authentication references
        if "authentication" in data:
            doc.authentication = data["authentication"]

        # Add assertion method references
        if "assertionMethod" in data:
            doc.assertion_method = data["assertionMethod"]

        # Add key agreement references
        if "keyAgreement" in data:
            doc.key_agreement = data["keyAgreement"]

        # Add capability invocation references
        if "capabilityInvocation" in data:
            doc.capability_invocation = data["capabilityInvocation"]

        # Add capability delegation references
        if "capabilityDelegation" in data:
            doc.capability_delegation = data["capabilityDelegation"]

        # Add services
        if "service" in data:
            for service_data in data["service"]:
                service = PQCService.from_dict(service_data)
                doc.service.append(service)

        # Extract metadata (everything else except known DID fields)
        excluded_fields = {
            "@context", "id", "alsoKnownAs", "verificationMethod",
            "authentication", "assertionMethod", "keyAgreement",
            "capabilityInvocation", "capabilityDelegation", "service", "proof"
        }

        metadata = {
            key: value for key, value in data.items()
            if key not in excluded_fields
        }

        if metadata:
            doc.add_metadata(metadata)

        # Add proof
        if "proof" in data:
            doc.add_proof(data["proof"])

        return doc

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> 'PQCDIDDocument':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def get_verification_method(self, vm_id: str) -> Optional[PQCVerificationMethod]:
        """Get verification method by ID."""
        for vm in self.verification_method:
            if vm.id == vm_id or vm.id.endswith(vm_id):
                return vm
        return None

    def get_service(self, service_id: str) -> Optional[PQCService]:
        """Get service by ID."""
        for service in self.service:
            if service.id == service_id or service.id.endswith(service_id):
                return service
        return None

    def validate(self) -> List[str]:
        """Validate DID document structure.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        if not self.id:
            errors.append("DID document must have an 'id' field")

        if not self.id.startswith("did:"):
            errors.append("DID 'id' must start with 'did:'")

        # Validate verification methods
        vm_ids = set()
        for vm in self.verification_method:
            if vm.id in vm_ids:
                errors.append(f"Duplicate verification method ID: {vm.id}")
            vm_ids.add(vm.id)

            if not vm.controller:
                errors.append(f"Verification method {vm.id} missing controller")

            if not vm.public_key_multibase:
                errors.append(f"Verification method {vm.id} missing public key")

        # Validate authentication references
        for auth_ref in self.authentication:
            if auth_ref not in vm_ids and not any(vm.id.endswith(auth_ref) for vm in self.verification_method):
                errors.append(f"Authentication reference '{auth_ref}' does not match any verification method")

        # Validate service IDs
        service_ids = set()
        for service in self.service:
            if service.id in service_ids:
                errors.append(f"Duplicate service ID: {service.id}")
            service_ids.add(service.id)

        return errors

    def is_valid(self) -> bool:
        """Check if DID document is valid."""
        return len(self.validate()) == 0
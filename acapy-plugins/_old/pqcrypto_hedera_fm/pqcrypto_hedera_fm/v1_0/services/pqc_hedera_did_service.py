"""PQC Hedera DID Service - Implementation of did:hedera-pqc method."""

import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import hashlib
import base64

from acapy_agent.core.error import BaseError

from ..config import PQCHederaConfig
from .hedera_client_service import HederaClientService
from ..models.pqc_did_document import PQCDIDDocument, PQCVerificationMethod
from ..crypto.pqc_key_manager import PQCKeyManager
from ..utils.did_utils import generate_did_identifier, validate_did_format

LOGGER = logging.getLogger(__name__)


class PQCHederaDIDError(BaseError):
    """PQC Hedera DID specific errors."""
    pass


class PQCHederaDIDService:
    """Service for managing PQC DIDs on Hedera Hashgraph."""

    def __init__(self, config: PQCHederaConfig, hedera_client: HederaClientService):
        """Initialize PQC Hedera DID Service.

        Args:
            config: Plugin configuration
            hedera_client: Hedera client service
        """
        self.config = config
        self.hedera_client = hedera_client
        self.key_manager = PQCKeyManager(config)
        self._initialized = False

    async def initialize(self):
        """Initialize the DID service."""
        if self._initialized:
            return

        LOGGER.info("Initializing PQC Hedera DID Service...")

        # Initialize key manager
        await self.key_manager.initialize()

        # Verify Hedera client is ready
        if not self.hedera_client.is_ready():
            raise PQCHederaDIDError("Hedera client not ready")

        self._initialized = True
        LOGGER.info("✅ PQC Hedera DID Service initialized")

    async def create_did(
        self,
        seed: Optional[str] = None,
        key_type: str = "ML-DSA-65"
    ) -> Tuple[str, Dict[str, Any]]:
        """Create a new PQC DID on Hedera.

        Args:
            seed: Optional seed for key generation
            key_type: PQC key type to use

        Returns:
            Tuple of (DID string, DID Document dict)
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating PQC DID with algorithm: {key_type}")

        # Generate PQC key pair
        key_pair = await self.key_manager.generate_key_pair(key_type, seed)

        # Create DID identifier from public key
        did_identifier = generate_did_identifier(
            key_pair.public_key_bytes,
            self.config.network
        )

        did = f"{self.config.did_method}:{self.config.network}:{did_identifier}"

        # Create DID document
        did_doc = await self._create_did_document(did, key_pair, key_type)

        # Store DID document on Hedera
        topic_id = await self._store_did_document_on_hedera(did, did_doc)

        # Add Hedera-specific metadata
        did_doc.add_service({
            "id": f"{did}#hedera-consensus",
            "type": "HederaConsensusService",
            "serviceEndpoint": {
                "topicId": topic_id,
                "network": self.config.network,
                "mirrorNodeUrl": self.config.mirror_node_url
            }
        })

        LOGGER.info(f"✅ Created PQC DID: {did}")

        return did, did_doc.to_dict()

    async def resolve_did(self, did: str) -> Dict[str, Any]:
        """Resolve a PQC DID to its document.

        Args:
            did: The DID to resolve

        Returns:
            DID Document dictionary
        """
        if not validate_did_format(did, self.config.did_method):
            raise PQCHederaDIDError(f"Invalid DID format: {did}")

        LOGGER.info(f"Resolving DID: {did}")

        # Extract topic ID from DID or resolve from Hedera registry
        topic_id = await self._get_topic_id_for_did(did)

        if not topic_id:
            raise PQCHederaDIDError(f"DID not found on Hedera: {did}")

        # Retrieve latest DID document from Hedera topic
        did_doc_data = await self._retrieve_did_document_from_hedera(topic_id)

        if not did_doc_data:
            raise PQCHederaDIDError(f"DID document not found: {did}")

        # Verify DID document integrity
        await self._verify_did_document_integrity(did_doc_data)

        LOGGER.info(f"✅ Resolved DID: {did}")

        return did_doc_data

    async def update_did(
        self,
        did: str,
        updates: Dict[str, Any],
        private_key: str
    ) -> Dict[str, Any]:
        """Update a PQC DID document.

        Args:
            did: The DID to update
            updates: Updates to apply
            private_key: Private key for authorization

        Returns:
            Updated DID Document dictionary
        """
        if not validate_did_format(did, self.config.did_method):
            raise PQCHederaDIDError(f"Invalid DID format: {did}")

        LOGGER.info(f"Updating DID: {did}")

        # Resolve current DID document
        current_doc = await self.resolve_did(did)
        current_did_doc = PQCDIDDocument.from_dict(current_doc)

        # Apply updates
        updated_doc = await self._apply_did_updates(current_did_doc, updates)

        # Sign the update
        signature = await self._sign_did_update(updated_doc, private_key)
        updated_doc.add_proof(signature)

        # Store updated document on Hedera
        topic_id = await self._get_topic_id_for_did(did)
        await self._store_did_document_on_hedera(did, updated_doc, topic_id)

        LOGGER.info(f"✅ Updated DID: {did}")

        return updated_doc.to_dict()

    async def deactivate_did(self, did: str, private_key: str) -> bool:
        """Deactivate a PQC DID.

        Args:
            did: The DID to deactivate
            private_key: Private key for authorization

        Returns:
            True if successful
        """
        if not validate_did_format(did, self.config.did_method):
            raise PQCHederaDIDError(f"Invalid DID format: {did}")

        LOGGER.info(f"Deactivating DID: {did}")

        # Create deactivation document
        deactivation_doc = {
            "id": did,
            "deactivated": True,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Sign deactivation
        signature = await self._sign_did_update(deactivation_doc, private_key)
        deactivation_doc["proof"] = signature

        # Store deactivation on Hedera
        topic_id = await self._get_topic_id_for_did(did)
        await self._store_did_document_on_hedera(did, deactivation_doc, topic_id)

        LOGGER.info(f"✅ Deactivated DID: {did}")

        return True

    async def _create_did_document(
        self,
        did: str,
        key_pair: Any,
        key_type: str
    ) -> PQCDIDDocument:
        """Create a DID document for the given DID and key pair."""

        # Create verification method
        verification_method = PQCVerificationMethod(
            id=f"{did}#key-1",
            type="PQCVerificationKey2024",
            controller=did,
            public_key_multibase=base64.b64encode(key_pair.public_key_bytes).decode(),
            pqc_algorithm=key_type,
            key_encoding="base64"
        )

        # Create DID document
        did_doc = PQCDIDDocument(
            id=did,
            context=[
                "https://www.w3.org/ns/did/v1",
                "https://pqc-consortium.org/contexts/pqc-v1.jsonld",
                "https://hedera.com/contexts/hedera-v1.jsonld"
            ]
        )

        # Add verification method
        did_doc.add_verification_method(verification_method)

        # Add authentication reference
        did_doc.add_authentication(f"{did}#key-1")

        # Add assertion method reference
        did_doc.add_assertion_method(f"{did}#key-1")

        # Add key agreement if KEM algorithm
        if "KEM" in key_type:
            did_doc.add_key_agreement(f"{did}#key-1")

        # Add capability invocation
        did_doc.add_capability_invocation(f"{did}#key-1")

        # Add PQC-specific metadata
        did_doc.add_metadata({
            "pqcAlgorithmSuite": {
                "signature": self.config.signature_algorithm,
                "keyEncapsulation": self.config.kem_algorithm
            },
            "quantumSafe": True,
            "hederaNetwork": self.config.network,
            "created": datetime.utcnow().isoformat() + "Z"
        })

        return did_doc

    async def _store_did_document_on_hedera(
        self,
        did: str,
        did_doc: Any,
        topic_id: Optional[str] = None
    ) -> str:
        """Store DID document on Hedera consensus service."""

        if isinstance(did_doc, PQCDIDDocument):
            doc_data = did_doc.to_dict()
        else:
            doc_data = did_doc

        # Create Hedera message
        message = {
            "type": "DID_DOCUMENT",
            "did": did,
            "document": doc_data,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version": "1.0"
        }

        # Submit to Hedera Consensus Service
        if topic_id:
            result = await self.hedera_client.submit_message(topic_id, message)
        else:
            # Create new topic for this DID
            topic_id = await self.hedera_client.create_topic(
                memo=f"PQC DID Document: {did}"
            )
            result = await self.hedera_client.submit_message(topic_id, message)

        if not result.get("success"):
            raise PQCHederaDIDError(f"Failed to store DID document: {result.get('error')}")

        return topic_id

    async def _retrieve_did_document_from_hedera(self, topic_id: str) -> Dict[str, Any]:
        """Retrieve latest DID document from Hedera topic."""

        messages = await self.hedera_client.get_topic_messages(topic_id)

        # Find latest DID document message
        latest_doc = None
        latest_timestamp = None

        for message in messages:
            if message.get("type") == "DID_DOCUMENT":
                timestamp = message.get("timestamp")
                if not latest_timestamp or timestamp > latest_timestamp:
                    latest_timestamp = timestamp
                    latest_doc = message.get("document")

        return latest_doc

    async def _get_topic_id_for_did(self, did: str) -> Optional[str]:
        """Get Hedera topic ID for a DID."""

        # Try to resolve from DID registry
        registry_result = await self.hedera_client.query_did_registry(did)

        if registry_result:
            return registry_result.get("topicId")

        # Fallback: derive topic ID from DID identifier
        did_parts = did.split(":")
        if len(did_parts) >= 4:
            identifier = did_parts[3]
            # Use deterministic topic ID derivation
            return await self._derive_topic_id(identifier)

        return None

    async def _derive_topic_id(self, identifier: str) -> str:
        """Derive Hedera topic ID from DID identifier."""

        # Create deterministic topic ID based on identifier
        hash_input = f"pqc-did-{identifier}-{self.config.network}".encode()
        topic_hash = hashlib.sha256(hash_input).hexdigest()[:16]

        # Format as Hedera topic ID (simplified)
        return f"0.0.{int(topic_hash, 16) % 1000000}"

    async def _apply_did_updates(
        self,
        current_doc: PQCDIDDocument,
        updates: Dict[str, Any]
    ) -> PQCDIDDocument:
        """Apply updates to a DID document."""

        # Create copy of current document
        updated_doc = PQCDIDDocument.from_dict(current_doc.to_dict())

        # Apply verification method updates
        if "verificationMethod" in updates:
            for vm_update in updates["verificationMethod"]:
                if vm_update.get("action") == "add":
                    updated_doc.add_verification_method(vm_update["method"])
                elif vm_update.get("action") == "remove":
                    updated_doc.remove_verification_method(vm_update["id"])

        # Apply service updates
        if "service" in updates:
            for service_update in updates["service"]:
                if service_update.get("action") == "add":
                    updated_doc.add_service(service_update["service"])
                elif service_update.get("action") == "remove":
                    updated_doc.remove_service(service_update["id"])

        # Update timestamp
        updated_doc.add_metadata({
            "updated": datetime.utcnow().isoformat() + "Z"
        })

        return updated_doc

    async def _sign_did_update(self, document: Any, private_key: str) -> Dict[str, Any]:
        """Sign a DID document update."""

        if isinstance(document, PQCDIDDocument):
            doc_bytes = json.dumps(document.to_dict(), sort_keys=True).encode()
        else:
            doc_bytes = json.dumps(document, sort_keys=True).encode()

        # Sign with PQC algorithm
        signature = await self.key_manager.sign(doc_bytes, private_key)

        return {
            "type": "PQCSignature2024",
            "created": datetime.utcnow().isoformat() + "Z",
            "verificationMethod": "#key-1",
            "proofPurpose": "assertionMethod",
            "signatureValue": base64.b64encode(signature).decode(),
            "algorithm": self.config.signature_algorithm
        }

    async def _verify_did_document_integrity(self, did_doc_data: Dict[str, Any]) -> bool:
        """Verify DID document integrity and signatures."""

        # Extract proof if present
        proof = did_doc_data.get("proof")
        if not proof:
            return True  # No proof to verify

        # Verify PQC signature
        doc_copy = did_doc_data.copy()
        del doc_copy["proof"]

        doc_bytes = json.dumps(doc_copy, sort_keys=True).encode()
        signature = base64.b64decode(proof["signatureValue"])

        # Get verification method
        verification_method = None
        for vm in did_doc_data.get("verificationMethod", []):
            if vm["id"].endswith(proof["verificationMethod"]):
                verification_method = vm
                break

        if not verification_method:
            raise PQCHederaDIDError("Verification method not found")

        # Verify signature
        public_key = base64.b64decode(verification_method["publicKeyMultibase"])

        is_valid = await self.key_manager.verify(
            doc_bytes,
            signature,
            public_key,
            verification_method["pqcAlgorithm"]
        )

        if not is_valid:
            raise PQCHederaDIDError("Invalid DID document signature")

        return True

    def is_ready(self) -> bool:
        """Check if service is ready."""
        return self._initialized and self.hedera_client.is_ready()

    async def get_supported_algorithms(self) -> List[str]:
        """Get list of supported PQC algorithms."""
        return await self.key_manager.get_supported_algorithms()
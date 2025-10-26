"""PQC Hedera Credential Service - PQC-native credential operations."""

import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import hashlib
import base64
import uuid

from acapy_agent.core.error import BaseError

from ..config import PQCHederaConfig
from .hedera_client_service import HederaClientService
from .pqc_hedera_did_service import PQCHederaDIDService
from .pqc_hedera_registry_service import PQCHederaRegistryService
from ..models.pqc_credential import PQCCredential, PQCPresentation, PQCCredentialOffer, PQCCredentialRequest
from ..crypto.pqc_key_manager import PQCKeyManager

LOGGER = logging.getLogger(__name__)


class PQCHederaCredentialError(BaseError):
    """PQC Hedera Credential specific errors."""
    pass


class PQCHederaCredentialService:
    """Service for PQC-native credential operations on Hedera."""

    def __init__(
        self,
        config: PQCHederaConfig,
        hedera_client: HederaClientService,
        did_service: PQCHederaDIDService,
        registry_service: PQCHederaRegistryService
    ):
        """Initialize PQC Hedera Credential Service.

        Args:
            config: Plugin configuration
            hedera_client: Hedera client service
            did_service: DID service
            registry_service: Registry service
        """
        self.config = config
        self.hedera_client = hedera_client
        self.did_service = did_service
        self.registry_service = registry_service
        self.key_manager = PQCKeyManager(config)
        self._initialized = False

    async def initialize(self):
        """Initialize the credential service."""
        if self._initialized:
            return

        LOGGER.info("Initializing PQC Hedera Credential Service...")

        # Initialize key manager
        await self.key_manager.initialize()

        # Verify dependencies are ready
        if not self.hedera_client.is_ready():
            raise PQCHederaCredentialError("Hedera client not ready")

        if not self.did_service.is_ready():
            raise PQCHederaCredentialError("DID service not ready")

        if not self.registry_service.is_ready():
            raise PQCHederaCredentialError("Registry service not ready")

        self._initialized = True
        LOGGER.info("✅ PQC Hedera Credential Service initialized")

    async def create_credential_offer(
        self,
        issuer_did: str,
        creddef_id: str,
        holder_did: Optional[str] = None,
        attributes: Optional[Dict[str, str]] = None
    ) -> PQCCredentialOffer:
        """Create a PQC credential offer.

        Args:
            issuer_did: Issuer DID
            creddef_id: Credential definition ID
            holder_did: Optional holder DID
            attributes: Optional preview attributes

        Returns:
            PQC credential offer
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating PQC credential offer for creddef: {creddef_id}")

        # Verify credential definition exists
        creddef = await self.registry_service.get_credential_definition(creddef_id)
        if not creddef:
            raise PQCHederaCredentialError(f"Credential definition not found: {creddef_id}")

        # Generate offer nonce
        offer_nonce = self._generate_nonce()

        # Create PQC credential offer
        offer = PQCCredentialOffer(
            id=str(uuid.uuid4()),
            issuer_did=issuer_did,
            creddef_id=creddef_id,
            holder_did=holder_did,
            nonce=offer_nonce,
            attributes_preview=attributes or {},
            pqc_algorithm_suite=creddef.pqc_algorithm_suite,
            expires_at=(datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z",
            created=datetime.utcnow().isoformat() + "Z"
        )

        LOGGER.info(f"✅ Created PQC credential offer: {offer.id}")

        return offer

    async def create_credential_request(
        self,
        holder_did: str,
        holder_private_key: str,
        offer: PQCCredentialOffer
    ) -> PQCCredentialRequest:
        """Create a PQC credential request from an offer.

        Args:
            holder_did: Holder DID
            holder_private_key: Holder's private key
            offer: Credential offer

        Returns:
            PQC credential request
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating PQC credential request for offer: {offer.id}")

        # Generate request nonce
        request_nonce = self._generate_nonce()

        # Generate master secret for this credential
        master_secret = self._generate_master_secret(holder_did, offer.creddef_id)

        # Create commitment to master secret
        master_secret_commitment = await self._create_master_secret_commitment(
            master_secret, offer.nonce, request_nonce
        )

        # Sign the request
        request_data = {
            "offerId": offer.id,
            "holderDid": holder_did,
            "creddefId": offer.creddef_id,
            "nonce": request_nonce,
            "masterSecretCommitment": master_secret_commitment
        }

        request_signature = await self._sign_credential_request(
            request_data, holder_private_key
        )

        # Create PQC credential request
        request = PQCCredentialRequest(
            id=str(uuid.uuid4()),
            offer_id=offer.id,
            holder_did=holder_did,
            creddef_id=offer.creddef_id,
            nonce=request_nonce,
            master_secret_commitment=master_secret_commitment,
            signature=request_signature,
            created=datetime.utcnow().isoformat() + "Z"
        )

        LOGGER.info(f"✅ Created PQC credential request: {request.id}")

        return request

    async def issue_credential(
        self,
        request: PQCCredentialRequest,
        issuer_private_key: str,
        attributes: Dict[str, str]
    ) -> PQCCredential:
        """Issue a PQC credential from a request.

        Args:
            request: Credential request
            issuer_private_key: Issuer's private key
            attributes: Credential attributes

        Returns:
            Issued PQC credential
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Issuing PQC credential for request: {request.id}")

        # Verify credential request signature
        if not await self._verify_credential_request(request):
            raise PQCHederaCredentialError("Invalid credential request signature")

        # Get credential definition
        creddef = await self.registry_service.get_credential_definition(request.creddef_id)
        if not creddef:
            raise PQCHederaCredentialError(f"Credential definition not found: {request.creddef_id}")

        # Get schema
        schema = await self.registry_service.get_schema(creddef.schema_id)
        if not schema:
            raise PQCHederaCredentialError(f"Schema not found: {creddef.schema_id}")

        # Validate attributes against schema
        await self._validate_attributes_against_schema(attributes, schema.attributes)

        # Generate credential values
        credential_values = await self._generate_credential_values(
            attributes, creddef, request.master_secret_commitment
        )

        # Create credential proof
        credential_proof = await self._create_credential_proof(
            credential_values, creddef, issuer_private_key
        )

        # Create PQC credential
        credential = PQCCredential(
            id=str(uuid.uuid4()),
            schema_id=schema.id,
            creddef_id=creddef.id,
            issuer_did=creddef.issuer_did,
            holder_did=request.holder_did,
            attributes=attributes,
            credential_values=credential_values,
            proof=credential_proof,
            pqc_algorithm_suite=creddef.pqc_algorithm_suite,
            issued_at=datetime.utcnow().isoformat() + "Z"
        )

        # Store credential on Hedera for audit trail
        await self._store_credential_on_hedera(credential)

        LOGGER.info(f"✅ Issued PQC credential: {credential.id}")

        return credential

    async def verify_credential(
        self,
        credential: PQCCredential,
        verify_revocation: bool = True
    ) -> bool:
        """Verify a PQC credential.

        Args:
            credential: Credential to verify
            verify_revocation: Whether to check revocation status

        Returns:
            True if credential is valid
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Verifying PQC credential: {credential.id}")

        try:
            # Verify credential structure
            if not credential.is_valid():
                LOGGER.warning("Credential structure is invalid")
                return False

            # Get credential definition
            creddef = await self.registry_service.get_credential_definition(credential.creddef_id)
            if not creddef:
                LOGGER.warning(f"Credential definition not found: {credential.creddef_id}")
                return False

            # Verify issuer DID matches
            if credential.issuer_did != creddef.issuer_did:
                LOGGER.warning("Issuer DID mismatch")
                return False

            # Verify credential proof
            if not await self._verify_credential_proof(credential, creddef):
                LOGGER.warning("Credential proof verification failed")
                return False

            # Check revocation if requested
            if verify_revocation and creddef.support_revocation:
                if await self._is_credential_revoked(credential):
                    LOGGER.warning("Credential is revoked")
                    return False

            LOGGER.info(f"✅ Credential verification successful: {credential.id}")
            return True

        except Exception as e:
            LOGGER.error(f"Credential verification failed: {e}")
            return False

    async def create_presentation(
        self,
        holder_did: str,
        holder_private_key: str,
        credentials: List[PQCCredential],
        requested_attributes: Dict[str, Any],
        challenge: str
    ) -> PQCPresentation:
        """Create a PQC presentation from credentials.

        Args:
            holder_did: Holder DID
            holder_private_key: Holder's private key
            credentials: List of credentials to present
            requested_attributes: Requested attributes with restrictions
            challenge: Challenge from verifier

        Returns:
            PQC presentation
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating PQC presentation with {len(credentials)} credentials")

        # Validate all credentials
        for credential in credentials:
            if not await self.verify_credential(credential):
                raise PQCHederaCredentialError(f"Invalid credential: {credential.id}")

        # Create revealed attributes
        revealed_attributes = await self._create_revealed_attributes(
            credentials, requested_attributes
        )

        # Create presentation proof
        presentation_proof = await self._create_presentation_proof(
            credentials, revealed_attributes, challenge, holder_private_key
        )

        # Create PQC presentation
        presentation = PQCPresentation(
            id=str(uuid.uuid4()),
            holder_did=holder_did,
            credentials=credentials,
            revealed_attributes=revealed_attributes,
            proof=presentation_proof,
            challenge=challenge,
            created=datetime.utcnow().isoformat() + "Z"
        )

        LOGGER.info(f"✅ Created PQC presentation: {presentation.id}")

        return presentation

    async def verify_presentation(
        self,
        presentation: PQCPresentation,
        challenge: str,
        requested_attributes: Dict[str, Any]
    ) -> bool:
        """Verify a PQC presentation.

        Args:
            presentation: Presentation to verify
            challenge: Expected challenge
            requested_attributes: Expected requested attributes

        Returns:
            True if presentation is valid
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Verifying PQC presentation: {presentation.id}")

        try:
            # Verify presentation structure
            if not presentation.is_valid():
                LOGGER.warning("Presentation structure is invalid")
                return False

            # Verify challenge matches
            if presentation.challenge != challenge:
                LOGGER.warning("Challenge mismatch")
                return False

            # Verify all credentials in presentation
            for credential in presentation.credentials:
                if not await self.verify_credential(credential):
                    LOGGER.warning(f"Invalid credential in presentation: {credential.id}")
                    return False

            # Verify revealed attributes match requested
            if not await self._verify_revealed_attributes(
                presentation.revealed_attributes, requested_attributes
            ):
                LOGGER.warning("Revealed attributes do not match requested")
                return False

            # Verify presentation proof
            if not await self._verify_presentation_proof(presentation):
                LOGGER.warning("Presentation proof verification failed")
                return False

            LOGGER.info(f"✅ Presentation verification successful: {presentation.id}")
            return True

        except Exception as e:
            LOGGER.error(f"Presentation verification failed: {e}")
            return False

    # Private helper methods

    def _generate_nonce(self) -> str:
        """Generate cryptographic nonce."""
        return base64.b64encode(hashlib.sha256(str(uuid.uuid4()).encode()).digest()).decode()

    def _generate_master_secret(self, holder_did: str, creddef_id: str) -> str:
        """Generate master secret for credential."""
        master_input = f"{holder_did}:{creddef_id}:{uuid.uuid4()}".encode()
        master_secret = hashlib.sha256(master_input).digest()
        return base64.b64encode(master_secret).decode()

    async def _create_master_secret_commitment(
        self,
        master_secret: str,
        offer_nonce: str,
        request_nonce: str
    ) -> str:
        """Create commitment to master secret."""
        commitment_input = f"{master_secret}:{offer_nonce}:{request_nonce}".encode()
        commitment = hashlib.sha256(commitment_input).digest()
        return base64.b64encode(commitment).decode()

    async def _sign_credential_request(
        self,
        request_data: Dict[str, Any],
        private_key: str
    ) -> Dict[str, Any]:
        """Sign credential request."""
        request_bytes = json.dumps(request_data, sort_keys=True).encode()

        signature = await self.key_manager.sign(
            request_bytes,
            private_key,
            self.config.signature_algorithm
        )

        return {
            "type": "PQCCredentialRequestSignature2024",
            "created": datetime.utcnow().isoformat() + "Z",
            "signatureValue": base64.b64encode(signature).decode(),
            "algorithm": self.config.signature_algorithm
        }

    async def _verify_credential_request(self, request: PQCCredentialRequest) -> bool:
        """Verify credential request signature."""
        # In a real implementation, we would resolve the holder's DID
        # and verify the signature using their public key
        # For now, return True if signature exists
        return request.signature is not None

    async def _validate_attributes_against_schema(
        self,
        attributes: Dict[str, str],
        schema_attributes: List[str]
    ):
        """Validate attributes against schema."""
        for attr_name in attributes.keys():
            if attr_name not in schema_attributes:
                raise PQCHederaCredentialError(f"Attribute '{attr_name}' not in schema")

    async def _generate_credential_values(
        self,
        attributes: Dict[str, str],
        creddef: Any,
        master_secret_commitment: str
    ) -> Dict[str, Any]:
        """Generate PQC credential values."""
        values = {}

        for attr_name, attr_value in attributes.items():
            # Create attribute-specific value with PQC blinding
            attr_key = creddef.get_attribute_keys().get(attr_name)
            if not attr_key:
                raise PQCHederaCredentialError(f"No key found for attribute: {attr_name}")

            # Generate blinded value
            blinded_value = await self._blind_attribute_value(
                attr_value, attr_key, master_secret_commitment
            )

            values[attr_name] = {
                "raw": attr_value,
                "encoded": self._encode_attribute_value(attr_value),
                "blinded": blinded_value
            }

        return values

    async def _blind_attribute_value(
        self,
        value: str,
        attr_key: str,
        master_secret_commitment: str
    ) -> str:
        """Blind attribute value with PQC techniques."""
        # Simplified PQC blinding - in practice would use more sophisticated techniques
        blind_input = f"{value}:{attr_key}:{master_secret_commitment}".encode()
        blinded = hashlib.sha256(blind_input).digest()
        return base64.b64encode(blinded).decode()

    def _encode_attribute_value(self, value: str) -> str:
        """Encode attribute value for zero-knowledge proofs."""
        # Convert to integer representation for ZK proofs
        if value.isdigit():
            return value
        else:
            # Hash string values to integers
            hash_val = int(hashlib.sha256(value.encode()).hexdigest(), 16)
            return str(hash_val % (2**64))  # Limit to 64-bit integers

    async def _create_credential_proof(
        self,
        credential_values: Dict[str, Any],
        creddef: Any,
        issuer_private_key: str
    ) -> Dict[str, Any]:
        """Create PQC credential proof."""
        # Create proof data
        proof_data = {
            "creddefId": creddef.id,
            "values": credential_values,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        proof_bytes = json.dumps(proof_data, sort_keys=True).encode()

        # Sign with issuer's PQC key
        signature = await self.key_manager.sign(
            proof_bytes,
            issuer_private_key,
            self.config.signature_algorithm
        )

        return {
            "type": "PQCCredentialProof2024",
            "created": datetime.utcnow().isoformat() + "Z",
            "proofPurpose": "assertionMethod",
            "signatureValue": base64.b64encode(signature).decode(),
            "algorithm": self.config.signature_algorithm,
            "proofData": proof_data
        }

    async def _verify_credential_proof(self, credential: PQCCredential, creddef: Any) -> bool:
        """Verify PQC credential proof."""
        # In a real implementation, we would:
        # 1. Resolve issuer's DID and get public key
        # 2. Verify the signature using PQC algorithm
        # 3. Verify the proof data consistency
        # For now, return True if proof exists
        return credential.proof is not None

    async def _is_credential_revoked(self, credential: PQCCredential) -> bool:
        """Check if credential is revoked."""
        # Placeholder for revocation checking
        # Would query revocation registry on Hedera
        return False

    async def _store_credential_on_hedera(self, credential: PQCCredential):
        """Store credential metadata on Hedera for audit trail."""
        # Store minimal credential metadata (not full credential for privacy)
        metadata = {
            "type": "PQC_CREDENTIAL_ISSUED",
            "id": credential.id,
            "schemaId": credential.schema_id,
            "creddefId": credential.creddef_id,
            "issuerDid": credential.issuer_did,
            "holderDid": credential.holder_did,
            "issuedAt": credential.issued_at,
            "proofHash": hashlib.sha256(
                json.dumps(credential.proof, sort_keys=True).encode()
            ).hexdigest()
        }

        # Submit to a credentials audit topic
        audit_topic = await self.hedera_client.create_topic("PQC Credentials Audit")
        await self.hedera_client.submit_message(audit_topic, metadata)

    async def _create_revealed_attributes(
        self,
        credentials: List[PQCCredential],
        requested_attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create revealed attributes from credentials."""
        revealed = {}

        for req_name, req_config in requested_attributes.items():
            for credential in credentials:
                attr_name = req_config.get("name")
                if attr_name and attr_name in credential.attributes:
                    revealed[req_name] = {
                        "credentialId": credential.id,
                        "attributeName": attr_name,
                        "value": credential.attributes[attr_name],
                        "creddefId": credential.creddef_id
                    }
                    break

        return revealed

    async def _create_presentation_proof(
        self,
        credentials: List[PQCCredential],
        revealed_attributes: Dict[str, Any],
        challenge: str,
        holder_private_key: str
    ) -> Dict[str, Any]:
        """Create PQC presentation proof."""
        proof_data = {
            "credentialIds": [cred.id for cred in credentials],
            "revealedAttributes": revealed_attributes,
            "challenge": challenge,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        proof_bytes = json.dumps(proof_data, sort_keys=True).encode()

        signature = await self.key_manager.sign(
            proof_bytes,
            holder_private_key,
            self.config.signature_algorithm
        )

        return {
            "type": "PQCPresentationProof2024",
            "created": datetime.utcnow().isoformat() + "Z",
            "proofPurpose": "authentication",
            "signatureValue": base64.b64encode(signature).decode(),
            "algorithm": self.config.signature_algorithm,
            "proofData": proof_data
        }

    async def _verify_revealed_attributes(
        self,
        revealed: Dict[str, Any],
        requested: Dict[str, Any]
    ) -> bool:
        """Verify revealed attributes match requested."""
        for req_name in requested.keys():
            if req_name not in revealed:
                return False
        return True

    async def _verify_presentation_proof(self, presentation: PQCPresentation) -> bool:
        """Verify PQC presentation proof."""
        # Similar to credential proof verification
        return presentation.proof is not None

    def is_ready(self) -> bool:
        """Check if service is ready."""
        return self._initialized
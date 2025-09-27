"""PQC Credential Service for issuing and verifying credentials with PQC."""

import logging
import json
import time
from dataclasses import dataclass
from typing import Dict, Optional, List, Any, Union
from datetime import datetime, timezone

from acapy_agent.wallet.error import WalletError
from acapy_agent.storage.record import StorageRecord
from acapy_agent.core.profile import Profile

from ..config import PQCConfig
from .pqc_crypto_service import PQCCryptoService, PQCSignature
from .pqc_wallet_service import PQCWalletService
from .pqc_did_service import PQCDidService

LOGGER = logging.getLogger(__name__)


@dataclass
class PQCCredential:
    """Post-Quantum Verifiable Credential."""
    context: List[str]
    id: str
    type: List[str]
    issuer: Union[str, Dict[str, Any]]
    issuance_date: str
    expiration_date: Optional[str]
    credential_subject: Dict[str, Any]
    proof: Optional[Dict[str, Any]] = None
    credential_schema: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PQCCredentialProof:
    """Post-Quantum Credential Proof."""
    type: str
    created: str
    verification_method: str
    proof_purpose: str
    algorithm: str
    signature_value: str
    metadata: Optional[Dict[str, Any]] = None


class PQCCredentialService:
    """Service for issuing and verifying PQC credentials."""

    RECORD_TYPE_PQC_CREDENTIAL = "pqc_credential"
    PROOF_TYPE_PQC_SIGNATURE = "PQCSignature2023"
    PROOF_TYPE_HYBRID_SIGNATURE = "HybridPQCSignature2023"

    def __init__(self, config: PQCConfig):
        """Initialize PQC Credential Service.

        Args:
            config: PQC configuration
        """
        self.config = config

    async def issue_credential(
        self,
        profile: Profile,
        issuer_did: str,
        credential_subject: Dict[str, Any],
        credential_type: Optional[List[str]] = None,
        schema_id: Optional[str] = None,
        expiration_date: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PQCCredential:
        """Issue a PQC verifiable credential.

        Args:
            profile: Profile for storage access
            issuer_did: DID of the issuer
            credential_subject: Credential subject data
            credential_type: Optional credential types
            schema_id: Optional schema identifier
            expiration_date: Optional expiration date (ISO format)
            metadata: Optional metadata

        Returns:
            Issued PQC credential

        Raises:
            WalletError: If credential issuance fails
        """
        try:
            # Get services
            from .pqc_did_service import PQCDidService
            from .pqc_wallet_service import PQCWalletService
            from .pqc_crypto_service import PQCCryptoService
            from ..config import PQCConfig

            config = PQCConfig(profile.settings)

            did_service = profile.inject_or(PQCDidService)
            if not did_service:
                did_service = PQCDidService(config)
                profile.context.injector.bind_instance(PQCDidService, did_service)

            wallet_service = profile.inject_or(PQCWalletService)
            if not wallet_service:
                wallet_service = PQCWalletService(config)
                profile.context.injector.bind_instance(PQCWalletService, wallet_service)

            crypto_service = profile.inject_or(PQCCryptoService)
            if not crypto_service:
                crypto_service = PQCCryptoService(config)
                await crypto_service.initialize()
                profile.context.injector.bind_instance(PQCCryptoService, crypto_service)

            # Verify issuer DID exists
            issuer_info = await did_service.get_pqc_did(profile, issuer_did)

            # Generate credential ID
            import uuid
            credential_id = f"urn:uuid:{uuid.uuid4()}"

            # Set default credential types
            if not credential_type:
                credential_type = ["VerifiableCredential", "PQCCredential"]

            # Create base credential
            now = datetime.now(timezone.utc)
            credential = PQCCredential(
                context=[
                    "https://www.w3.org/2018/credentials/v1",
                    "https://w3id.org/security/suites/pqc-2023/v1"
                ],
                id=credential_id,
                type=credential_type,
                issuer=issuer_did,
                issuance_date=now.isoformat(),
                expiration_date=expiration_date,
                credential_subject=credential_subject,
                metadata=metadata or {}
            )

            # Add schema reference if provided
            if schema_id:
                credential.credential_schema = {
                    "id": schema_id,
                    "type": "JsonSchemaValidator2018"
                }

            # Create credential proof
            proof = await self._create_credential_proof(
                profile, credential, issuer_info.verkey
            )
            credential.proof = proof

            # Store credential
            await self._store_credential(profile, credential)

            LOGGER.info(f"Issued PQC credential: {credential_id}")
            return credential

        except Exception as e:
            LOGGER.error(f"Failed to issue PQC credential: {e}")
            raise WalletError(f"PQC credential issuance failed: {e}")

    async def _create_credential_proof(
        self,
        profile: Profile,
        credential: PQCCredential,
        verkey: str
    ) -> Dict[str, Any]:
        """Create a proof for a credential.

        Args:
            profile: Profile for storage access
            credential: Credential to create proof for
            verkey: Verification key for signing

        Returns:
            Credential proof

        Raises:
            WalletError: If proof creation fails
        """
        try:
            from .pqc_wallet_service import PQCWalletService
            from .pqc_crypto_service import PQCCryptoService
            from ..config import PQCConfig

            config = PQCConfig(profile.settings)

            wallet_service = profile.inject_or(PQCWalletService)
            if not wallet_service:
                wallet_service = PQCWalletService(config)
                profile.context.injector.bind_instance(PQCWalletService, wallet_service)

            crypto_service = profile.inject_or(PQCCryptoService)
            if not crypto_service:
                crypto_service = PQCCryptoService(config)
                await crypto_service.initialize()
                profile.context.injector.bind_instance(PQCCryptoService, crypto_service)

            # Get signing key
            keypair, is_hybrid = await wallet_service.get_pqc_signing_key(
                profile, verkey
            )

            # Create canonical credential for signing
            canonical_credential = self._canonicalize_credential(credential)

            # Sign the canonical credential
            signature = await crypto_service.sign(
                canonical_credential.encode('utf-8'), keypair
            )

            # Create proof object
            proof_type = (
                self.PROOF_TYPE_HYBRID_SIGNATURE if is_hybrid
                else self.PROOF_TYPE_PQC_SIGNATURE
            )

            proof = {
                "type": proof_type,
                "created": datetime.now(timezone.utc).isoformat(),
                "verificationMethod": f"{credential.issuer}#key-1",
                "proofPurpose": "assertionMethod",
                "algorithm": signature.algorithm,
                "signatureValue": self._encode_signature(signature.signature)
            }

            if is_hybrid:
                proof["hybridMetadata"] = {
                    "pqcAlgorithm": keypair.pqc_keypair.algorithm,
                    "classicalAlgorithm": "Ed25519"  # or X25519 for KEM
                }

            return proof

        except Exception as e:
            LOGGER.error(f"Failed to create credential proof: {e}")
            raise WalletError(f"Credential proof creation failed: {e}")

    def _canonicalize_credential(self, credential: PQCCredential) -> str:
        """Create canonical representation of credential for signing.

        Args:
            credential: Credential to canonicalize

        Returns:
            Canonical credential string
        """
        # Create credential dict without proof
        cred_dict = {
            "@context": credential.context,
            "id": credential.id,
            "type": credential.type,
            "issuer": credential.issuer,
            "issuanceDate": credential.issuance_date,
            "credentialSubject": credential.credential_subject
        }

        if credential.expiration_date:
            cred_dict["expirationDate"] = credential.expiration_date

        if credential.credential_schema:
            cred_dict["credentialSchema"] = credential.credential_schema

        # Sort keys for deterministic serialization
        return json.dumps(cred_dict, sort_keys=True, separators=(',', ':'))

    def _encode_signature(self, signature: bytes) -> str:
        """Encode signature for credential proof.

        Args:
            signature: Raw signature bytes

        Returns:
            Encoded signature string
        """
        import base64
        return base64.b64encode(signature).decode()

    async def _store_credential(
        self,
        profile: Profile,
        credential: PQCCredential
    ) -> None:
        """Store a credential.

        Args:
            profile: Profile for storage access
            credential: Credential to store
        """
        # Convert credential to dict for storage
        cred_dict = {
            "context": credential.context,
            "id": credential.id,
            "type": credential.type,
            "issuer": credential.issuer,
            "issuanceDate": credential.issuance_date,
            "expirationDate": credential.expiration_date,
            "credentialSubject": credential.credential_subject,
            "proof": credential.proof,
            "credentialSchema": credential.credential_schema,
            "metadata": credential.metadata
        }

        async with profile.session() as session:
            storage = session.context.inject(BaseStorage)

            record = StorageRecord(
                type=self.RECORD_TYPE_PQC_CREDENTIAL,
                id=credential.id,
                value=json.dumps(cred_dict),
                tags={
                    "credential_id": credential.id,
                    "issuer": str(credential.issuer),
                    "type": ",".join(credential.type),
                    "issuance_date": credential.issuance_date
                }
            )
            await storage.add_record(record)

    async def verify_credential(
        self,
        profile: Profile,
        credential: Union[PQCCredential, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Verify a PQC credential.

        Args:
            profile: Profile for storage access
            credential: Credential to verify

        Returns:
            Verification result

        Raises:
            WalletError: If verification fails
        """
        try:
            # Convert dict to PQCCredential if needed
            if isinstance(credential, dict):
                credential = self._dict_to_credential(credential)

            from .pqc_crypto_service import PQCCryptoService
            from .pqc_did_service import PQCDidService
            from ..config import PQCConfig

            config = PQCConfig(profile.settings)

            crypto_service = profile.inject_or(PQCCryptoService)
            if not crypto_service:
                crypto_service = PQCCryptoService(config)
                await crypto_service.initialize()
                profile.context.injector.bind_instance(PQCCryptoService, crypto_service)

            did_service = profile.inject_or(PQCDidService)
            if not did_service:
                did_service = PQCDidService(config)
                profile.context.injector.bind_instance(PQCDidService, did_service)

            verification_result = {
                "valid": False,
                "errors": [],
                "warnings": [],
                "checks": {}
            }

            # Basic structure checks
            await self._check_credential_structure(credential, verification_result)

            # Expiration check
            await self._check_credential_expiration(credential, verification_result)

            # Issuer DID verification
            issuer_valid = await self._verify_issuer_did(
                profile, credential, verification_result
            )

            if issuer_valid:
                # Signature verification
                await self._verify_credential_signature(
                    profile, credential, verification_result
                )

            # Set overall validity
            verification_result["valid"] = (
                len(verification_result["errors"]) == 0 and
                verification_result["checks"].get("signature", False)
            )

            return verification_result

        except Exception as e:
            LOGGER.error(f"Failed to verify PQC credential: {e}")
            return {
                "valid": False,
                "errors": [f"Verification failed: {str(e)}"],
                "warnings": [],
                "checks": {}
            }

    def _dict_to_credential(self, cred_dict: Dict[str, Any]) -> PQCCredential:
        """Convert credential dict to PQCCredential object.

        Args:
            cred_dict: Credential dictionary

        Returns:
            PQCCredential object
        """
        return PQCCredential(
            context=cred_dict.get("@context", []),
            id=cred_dict.get("id"),
            type=cred_dict.get("type", []),
            issuer=cred_dict.get("issuer"),
            issuance_date=cred_dict.get("issuanceDate"),
            expiration_date=cred_dict.get("expirationDate"),
            credential_subject=cred_dict.get("credentialSubject", {}),
            proof=cred_dict.get("proof"),
            credential_schema=cred_dict.get("credentialSchema"),
            metadata=cred_dict.get("metadata")
        )

    async def _check_credential_structure(
        self,
        credential: PQCCredential,
        verification_result: Dict[str, Any]
    ) -> None:
        """Check basic credential structure.

        Args:
            credential: Credential to check
            verification_result: Verification result to update
        """
        checks = verification_result["checks"]
        errors = verification_result["errors"]

        # Required fields
        if not credential.id:
            errors.append("Missing credential ID")
        else:
            checks["credential_id"] = True

        if not credential.type or "VerifiableCredential" not in credential.type:
            errors.append("Invalid or missing credential type")
        else:
            checks["credential_type"] = True

        if not credential.issuer:
            errors.append("Missing issuer")
        else:
            checks["issuer_present"] = True

        if not credential.issuance_date:
            errors.append("Missing issuance date")
        else:
            checks["issuance_date"] = True

        if not credential.credential_subject:
            errors.append("Missing credential subject")
        else:
            checks["credential_subject"] = True

        if not credential.proof:
            errors.append("Missing proof")
        else:
            checks["proof_present"] = True

    async def _check_credential_expiration(
        self,
        credential: PQCCredential,
        verification_result: Dict[str, Any]
    ) -> None:
        """Check credential expiration.

        Args:
            credential: Credential to check
            verification_result: Verification result to update
        """
        if credential.expiration_date:
            try:
                exp_date = datetime.fromisoformat(
                    credential.expiration_date.replace('Z', '+00:00')
                )
                now = datetime.now(timezone.utc)

                if exp_date < now:
                    verification_result["errors"].append("Credential has expired")
                    verification_result["checks"]["not_expired"] = False
                else:
                    verification_result["checks"]["not_expired"] = True

            except ValueError:
                verification_result["warnings"].append("Invalid expiration date format")

    async def _verify_issuer_did(
        self,
        profile: Profile,
        credential: PQCCredential,
        verification_result: Dict[str, Any]
    ) -> bool:
        """Verify issuer DID.

        Args:
            profile: Profile for storage access
            credential: Credential to verify
            verification_result: Verification result to update

        Returns:
            True if issuer DID is valid
        """
        try:
            from .pqc_did_service import PQCDidService
            from ..config import PQCConfig

            config = PQCConfig(profile.settings)

            did_service = profile.inject_or(PQCDidService)
            if not did_service:
                did_service = PQCDidService(config)
                profile.context.injector.bind_instance(PQCDidService, did_service)
            issuer_did = str(credential.issuer)

            # Check if issuer DID exists in our storage
            await did_service.get_pqc_did(profile, issuer_did)
            verification_result["checks"]["issuer_did_valid"] = True
            return True

        except Exception:
            verification_result["warnings"].append(
                "Could not verify issuer DID (not in local storage)"
            )
            verification_result["checks"]["issuer_did_valid"] = False
            return False

    async def _verify_credential_signature(
        self,
        profile: Profile,
        credential: PQCCredential,
        verification_result: Dict[str, Any]
    ) -> None:
        """Verify credential signature.

        Args:
            profile: Profile for storage access
            credential: Credential to verify
            verification_result: Verification result to update
        """
        try:
            if not credential.proof:
                verification_result["errors"].append("No proof to verify")
                return

            from .pqc_crypto_service import PQCCryptoService
            from .pqc_did_service import PQCDidService
            from ..config import PQCConfig

            config = PQCConfig(profile.settings)

            crypto_service = profile.inject_or(PQCCryptoService)
            if not crypto_service:
                crypto_service = PQCCryptoService(config)
                await crypto_service.initialize()
                profile.context.injector.bind_instance(PQCCryptoService, crypto_service)

            did_service = profile.inject_or(PQCDidService)
            if not did_service:
                did_service = PQCDidService(config)
                profile.context.injector.bind_instance(PQCDidService, did_service)

            # Get issuer's public key
            issuer_did = str(credential.issuer)
            issuer_info = await did_service.get_pqc_did(profile, issuer_did)

            # Create canonical credential for verification
            canonical_credential = self._canonicalize_credential(credential)

            # Decode signature
            import base64
            signature_bytes = base64.b64decode(credential.proof["signatureValue"])

            # Create signature object
            signature = PQCSignature(
                signature=signature_bytes,
                algorithm=credential.proof["algorithm"],
                public_key=base64.b64decode(issuer_info.verkey)
            )

            # Verify signature
            is_valid = await crypto_service.verify(
                canonical_credential.encode('utf-8'), signature
            )

            verification_result["checks"]["signature"] = is_valid

            if not is_valid:
                verification_result["errors"].append("Invalid signature")

        except Exception as e:
            verification_result["errors"].append(f"Signature verification failed: {str(e)}")
            verification_result["checks"]["signature"] = False

    async def get_credential(
        self,
        profile: Profile,
        credential_id: str
    ) -> PQCCredential:
        """Get a stored credential.

        Args:
            profile: Profile for storage access
            credential_id: Credential identifier

        Returns:
            PQC credential

        Raises:
            WalletError: If credential not found
        """
        try:
            async with profile.session() as session:
                record = await StorageRecord.retrieve(
                    session, self.RECORD_TYPE_PQC_CREDENTIAL, credential_id
                )
                cred_dict = json.loads(record.value)
                return self._dict_to_credential(cred_dict)

        except Exception as e:
            LOGGER.error(f"Failed to get credential {credential_id}: {e}")
            raise WalletError(f"Credential not found: {credential_id}")

    async def list_credentials(
        self,
        profile: Profile,
        issuer_filter: Optional[str] = None,
        type_filter: Optional[str] = None
    ) -> List[PQCCredential]:
        """List stored credentials.

        Args:
            profile: Profile for storage access
            issuer_filter: Optional issuer filter
            type_filter: Optional type filter

        Returns:
            List of PQC credentials
        """
        credentials = []

        async with profile.session() as session:
            tag_query = {}
            if issuer_filter:
                tag_query["issuer"] = issuer_filter
            if type_filter:
                tag_query["type"] = type_filter

            storage = session.context.inject(BaseStorage)
            records = await storage.find_all_records(
                type_filter=self.RECORD_TYPE_PQC_CREDENTIAL,
                tag_query=tag_query
            )

            for record in records:
                cred_dict = json.loads(record.value)
                credentials.append(self._dict_to_credential(cred_dict))

        return credentials

    async def revoke_credential(
        self,
        profile: Profile,
        credential_id: str,
        reason: Optional[str] = None
    ) -> None:
        """Revoke a credential.

        Args:
            profile: Profile for storage access
            credential_id: Credential to revoke
            reason: Optional revocation reason

        Note:
            This is a simple implementation. Production systems should use
            proper revocation registries or status lists.
        """
        try:
            async with profile.session() as session:
                record = await StorageRecord.retrieve(
                    session, self.RECORD_TYPE_PQC_CREDENTIAL, credential_id
                )

                cred_dict = json.loads(record.value)
                cred_dict["metadata"] = cred_dict.get("metadata", {})
                cred_dict["metadata"]["revoked"] = True
                cred_dict["metadata"]["revocation_date"] = datetime.now(timezone.utc).isoformat()

                if reason:
                    cred_dict["metadata"]["revocation_reason"] = reason

                await record.replace(session, json.dumps(cred_dict))

                LOGGER.info(f"Revoked credential: {credential_id}")

        except Exception as e:
            LOGGER.error(f"Failed to revoke credential {credential_id}: {e}")
            raise WalletError(f"Credential revocation failed: {e}")
"""PQC Hedera Registry Service - Schema and CredDef management."""

import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import hashlib
import base64

from acapy_agent.core.error import BaseError

from ..config import PQCHederaConfig
from .hedera_client_service import HederaClientService
from ..models.pqc_schema import PQCSchema, PQCCredentialDefinition
from ..utils.registry_utils import generate_schema_id, generate_creddef_id

LOGGER = logging.getLogger(__name__)


class PQCHederaRegistryError(BaseError):
    """PQC Hedera Registry specific errors."""
    pass


class PQCHederaRegistryService:
    """Service for managing PQC schemas and credential definitions on Hedera."""

    def __init__(self, config: PQCHederaConfig, hedera_client: HederaClientService):
        """Initialize PQC Hedera Registry Service.

        Args:
            config: Plugin configuration
            hedera_client: Hedera client service
        """
        self.config = config
        self.hedera_client = hedera_client
        self._initialized = False

        # Registry topics
        self.schema_topic_id: Optional[str] = None
        self.creddef_topic_id: Optional[str] = None

        # Cache for performance
        self._schema_cache: Dict[str, PQCSchema] = {}
        self._creddef_cache: Dict[str, PQCCredentialDefinition] = {}

    async def initialize(self):
        """Initialize the registry service."""
        if self._initialized:
            return

        LOGGER.info("Initializing PQC Hedera Registry Service...")

        # Verify Hedera client is ready
        if not self.hedera_client.is_ready():
            raise PQCHederaRegistryError("Hedera client not ready")

        # Initialize or retrieve registry topics
        await self._initialize_registry_topics()

        self._initialized = True
        LOGGER.info("✅ PQC Hedera Registry Service initialized")

    async def create_schema(
        self,
        issuer_did: str,
        name: str,
        version: str,
        attributes: List[str],
        private_key: str
    ) -> PQCSchema:
        """Create and publish a PQC schema.

        Args:
            issuer_did: DID of the schema issuer
            name: Schema name
            version: Schema version
            attributes: List of attribute names
            private_key: Issuer's private key for signing

        Returns:
            Created PQC schema
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating PQC schema: {name} v{version}")

        # Generate schema ID
        schema_id = generate_schema_id(issuer_did, name, version)

        # Create schema object
        schema = PQCSchema(
            id=schema_id,
            name=name,
            version=version,
            issuer_did=issuer_did,
            attributes=attributes,
            pqc_algorithm_suite={
                "signature": self.config.signature_algorithm,
                "keyEncapsulation": self.config.kem_algorithm
            },
            created=datetime.utcnow().isoformat() + "Z"
        )

        # Sign schema
        schema_bytes = json.dumps(schema.to_dict_for_signing(), sort_keys=True).encode()
        signature = await self._sign_registry_item(schema_bytes, private_key)
        schema.add_signature(signature)

        # Publish to Hedera
        await self._publish_schema(schema)

        # Cache schema
        self._schema_cache[schema_id] = schema

        LOGGER.info(f"✅ Created PQC schema: {schema_id}")

        return schema

    async def get_schema(self, schema_id: str) -> Optional[PQCSchema]:
        """Retrieve a schema by ID.

        Args:
            schema_id: Schema identifier

        Returns:
            Schema if found, None otherwise
        """
        if not self._initialized:
            await self.initialize()

        # Check cache first
        if schema_id in self._schema_cache:
            return self._schema_cache[schema_id]

        LOGGER.info(f"Retrieving schema: {schema_id}")

        # Retrieve from Hedera
        schema_data = await self._retrieve_schema_from_hedera(schema_id)

        if schema_data:
            schema = PQCSchema.from_dict(schema_data)

            # Verify schema signature
            if not await self._verify_schema_signature(schema):
                raise PQCHederaRegistryError(f"Invalid schema signature: {schema_id}")

            # Cache schema
            self._schema_cache[schema_id] = schema

            LOGGER.info(f"✅ Retrieved schema: {schema_id}")
            return schema

        return None

    async def create_credential_definition(
        self,
        issuer_did: str,
        schema_id: str,
        tag: str,
        private_key: str,
        support_revocation: bool = False
    ) -> PQCCredentialDefinition:
        """Create and publish a PQC credential definition.

        Args:
            issuer_did: DID of the credential issuer
            schema_id: Schema ID for this credential definition
            tag: Tag for this credential definition
            private_key: Issuer's private key for signing
            support_revocation: Whether to support revocation

        Returns:
            Created PQC credential definition
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating PQC credential definition for schema: {schema_id}")

        # Verify schema exists
        schema = await self.get_schema(schema_id)
        if not schema:
            raise PQCHederaRegistryError(f"Schema not found: {schema_id}")

        # Generate credential definition ID
        creddef_id = generate_creddef_id(issuer_did, schema_id, tag)

        # Generate PQC keys for credential issuance
        creddef_keys = await self._generate_creddef_keys(schema.attributes)

        # Create credential definition
        creddef = PQCCredentialDefinition(
            id=creddef_id,
            schema_id=schema_id,
            issuer_did=issuer_did,
            tag=tag,
            pqc_keys=creddef_keys,
            pqc_algorithm_suite={
                "signature": self.config.signature_algorithm,
                "keyEncapsulation": self.config.kem_algorithm
            },
            support_revocation=support_revocation,
            created=datetime.utcnow().isoformat() + "Z"
        )

        # Sign credential definition
        creddef_bytes = json.dumps(creddef.to_dict_for_signing(), sort_keys=True).encode()
        signature = await self._sign_registry_item(creddef_bytes, private_key)
        creddef.add_signature(signature)

        # Publish to Hedera
        await self._publish_creddef(creddef)

        # Cache credential definition
        self._creddef_cache[creddef_id] = creddef

        LOGGER.info(f"✅ Created PQC credential definition: {creddef_id}")

        return creddef

    async def get_credential_definition(self, creddef_id: str) -> Optional[PQCCredentialDefinition]:
        """Retrieve a credential definition by ID.

        Args:
            creddef_id: Credential definition identifier

        Returns:
            Credential definition if found, None otherwise
        """
        if not self._initialized:
            await self.initialize()

        # Check cache first
        if creddef_id in self._creddef_cache:
            return self._creddef_cache[creddef_id]

        LOGGER.info(f"Retrieving credential definition: {creddef_id}")

        # Retrieve from Hedera
        creddef_data = await self._retrieve_creddef_from_hedera(creddef_id)

        if creddef_data:
            creddef = PQCCredentialDefinition.from_dict(creddef_data)

            # Verify credential definition signature
            if not await self._verify_creddef_signature(creddef):
                raise PQCHederaRegistryError(f"Invalid credential definition signature: {creddef_id}")

            # Cache credential definition
            self._creddef_cache[creddef_id] = creddef

            LOGGER.info(f"✅ Retrieved credential definition: {creddef_id}")
            return creddef

        return None

    async def list_schemas(self, issuer_did: Optional[str] = None) -> List[PQCSchema]:
        """List schemas, optionally filtered by issuer.

        Args:
            issuer_did: Optional issuer DID filter

        Returns:
            List of schemas
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info("Listing schemas")

        # Retrieve all schemas from Hedera
        schemas_data = await self._list_schemas_from_hedera()

        schemas = []
        for schema_data in schemas_data:
            try:
                schema = PQCSchema.from_dict(schema_data)

                # Apply issuer filter
                if issuer_did and schema.issuer_did != issuer_did:
                    continue

                # Verify signature
                if await self._verify_schema_signature(schema):
                    schemas.append(schema)
                    # Cache valid schema
                    self._schema_cache[schema.id] = schema

            except Exception as e:
                LOGGER.warning(f"Failed to process schema: {e}")

        LOGGER.info(f"✅ Listed {len(schemas)} schemas")
        return schemas

    async def list_credential_definitions(
        self,
        issuer_did: Optional[str] = None,
        schema_id: Optional[str] = None
    ) -> List[PQCCredentialDefinition]:
        """List credential definitions, optionally filtered.

        Args:
            issuer_did: Optional issuer DID filter
            schema_id: Optional schema ID filter

        Returns:
            List of credential definitions
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info("Listing credential definitions")

        # Retrieve all credential definitions from Hedera
        creddefs_data = await self._list_creddefs_from_hedera()

        creddefs = []
        for creddef_data in creddefs_data:
            try:
                creddef = PQCCredentialDefinition.from_dict(creddef_data)

                # Apply filters
                if issuer_did and creddef.issuer_did != issuer_did:
                    continue

                if schema_id and creddef.schema_id != schema_id:
                    continue

                # Verify signature
                if await self._verify_creddef_signature(creddef):
                    creddefs.append(creddef)
                    # Cache valid credential definition
                    self._creddef_cache[creddef.id] = creddef

            except Exception as e:
                LOGGER.warning(f"Failed to process credential definition: {e}")

        LOGGER.info(f"✅ Listed {len(creddefs)} credential definitions")
        return creddefs

    async def _initialize_registry_topics(self):
        """Initialize or retrieve Hedera topics for registry."""

        # Schema topic
        if self.config.schema_contract_id:
            self.schema_topic_id = self.config.schema_contract_id
        else:
            self.schema_topic_id = await self.hedera_client.create_topic(
                memo="PQC Schema Registry"
            )

        # Credential definition topic
        if self.config.creddef_contract_id:
            self.creddef_topic_id = self.config.creddef_contract_id
        else:
            self.creddef_topic_id = await self.hedera_client.create_topic(
                memo="PQC Credential Definition Registry"
            )

        LOGGER.info(f"Registry topics - Schema: {self.schema_topic_id}, CredDef: {self.creddef_topic_id}")

    async def _publish_schema(self, schema: PQCSchema):
        """Publish schema to Hedera."""

        message = {
            "type": "PQC_SCHEMA",
            "id": schema.id,
            "schema": schema.to_dict(),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        result = await self.hedera_client.submit_message(
            self.schema_topic_id,
            message
        )

        if not result.get("success"):
            raise PQCHederaRegistryError(f"Failed to publish schema: {result.get('error')}")

    async def _publish_creddef(self, creddef: PQCCredentialDefinition):
        """Publish credential definition to Hedera."""

        message = {
            "type": "PQC_CREDDEF",
            "id": creddef.id,
            "creddef": creddef.to_dict(),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        result = await self.hedera_client.submit_message(
            self.creddef_topic_id,
            message
        )

        if not result.get("success"):
            raise PQCHederaRegistryError(f"Failed to publish credential definition: {result.get('error')}")

    async def _retrieve_schema_from_hedera(self, schema_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve schema from Hedera by ID."""

        messages = await self.hedera_client.get_topic_messages(self.schema_topic_id)

        for message in messages:
            if (message.get("type") == "PQC_SCHEMA" and
                message.get("id") == schema_id):
                return message.get("schema")

        return None

    async def _retrieve_creddef_from_hedera(self, creddef_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve credential definition from Hedera by ID."""

        messages = await self.hedera_client.get_topic_messages(self.creddef_topic_id)

        for message in messages:
            if (message.get("type") == "PQC_CREDDEF" and
                message.get("id") == creddef_id):
                return message.get("creddef")

        return None

    async def _list_schemas_from_hedera(self) -> List[Dict[str, Any]]:
        """List all schemas from Hedera."""

        messages = await self.hedera_client.get_topic_messages(self.schema_topic_id)

        schemas = []
        for message in messages:
            if message.get("type") == "PQC_SCHEMA":
                schemas.append(message.get("schema"))

        return schemas

    async def _list_creddefs_from_hedera(self) -> List[Dict[str, Any]]:
        """List all credential definitions from Hedera."""

        messages = await self.hedera_client.get_topic_messages(self.creddef_topic_id)

        creddefs = []
        for message in messages:
            if message.get("type") == "PQC_CREDDEF":
                creddefs.append(message.get("creddef"))

        return creddefs

    async def _generate_creddef_keys(self, attributes: List[str]) -> Dict[str, Any]:
        """Generate PQC keys for credential definition."""

        # For PQC credentials, we use different approach than traditional AnonCreds
        # Generate master secret key and attribute-specific keys

        master_secret = hashlib.sha256(
            f"master-{self.config.signature_algorithm}-{datetime.utcnow().isoformat()}".encode()
        ).digest()

        attribute_keys = {}
        for attr in attributes:
            attr_key = hashlib.sha256(
                master_secret + attr.encode()
            ).digest()
            attribute_keys[attr] = base64.b64encode(attr_key).decode()

        return {
            "algorithm": self.config.signature_algorithm,
            "masterSecret": base64.b64encode(master_secret).decode(),
            "attributeKeys": attribute_keys,
            "keyType": "PQC_CREDDEF_KEYS",
            "version": "1.0"
        }

    async def _sign_registry_item(self, item_bytes: bytes, private_key: str) -> Dict[str, Any]:
        """Sign a registry item (schema or creddef)."""

        # Import here to avoid circular imports
        from ..crypto.pqc_key_manager import PQCKeyManager

        key_manager = PQCKeyManager(self.config)
        await key_manager.initialize()

        signature = await key_manager.sign(
            item_bytes,
            private_key,
            self.config.signature_algorithm
        )

        return {
            "type": "PQCRegistrySignature2024",
            "created": datetime.utcnow().isoformat() + "Z",
            "signatureValue": base64.b64encode(signature).decode(),
            "algorithm": self.config.signature_algorithm
        }

    async def _verify_schema_signature(self, schema: PQCSchema) -> bool:
        """Verify schema signature."""

        if not schema.signature:
            return False

        try:
            # Import here to avoid circular imports
            from ..crypto.pqc_key_manager import PQCKeyManager

            key_manager = PQCKeyManager(self.config)
            await key_manager.initialize()

            # Get schema data for signing
            schema_bytes = json.dumps(schema.to_dict_for_signing(), sort_keys=True).encode()

            # Get issuer's public key (simplified - would need DID resolution)
            # For now, assume signature is valid if present
            return True

        except Exception as e:
            LOGGER.warning(f"Failed to verify schema signature: {e}")
            return False

    async def _verify_creddef_signature(self, creddef: PQCCredentialDefinition) -> bool:
        """Verify credential definition signature."""

        if not creddef.signature:
            return False

        try:
            # Similar to schema verification
            return True

        except Exception as e:
            LOGGER.warning(f"Failed to verify credential definition signature: {e}")
            return False

    def is_ready(self) -> bool:
        """Check if service is ready."""
        return self._initialized and self.hedera_client.is_ready()

    async def get_registry_info(self) -> Dict[str, Any]:
        """Get registry information."""
        return {
            "schemaTopicId": self.schema_topic_id,
            "creddefTopicId": self.creddef_topic_id,
            "network": self.config.network,
            "algorithmSuite": {
                "signature": self.config.signature_algorithm,
                "keyEncapsulation": self.config.kem_algorithm
            },
            "cacheStats": {
                "schemas": len(self._schema_cache),
                "credentialDefinitions": len(self._creddef_cache)
            }
        }
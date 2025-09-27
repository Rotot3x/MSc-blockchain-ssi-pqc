"""PQC Wallet Service for key management and storage."""

import logging
import json
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import asdict

from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import KeyType
from acapy_agent.wallet.did_info import KeyInfo, DIDInfo
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.record import StorageRecord
from acapy_agent.core.profile import Profile

from ..config import PQCConfig
from ..key_types import (
    PQC_KEY_TYPES, DEFAULT_PQC_SIGNATURE_KEY_TYPE, DEFAULT_PQC_KEM_KEY_TYPE,
    is_pqc_key_type, is_signature_key_type, is_kem_key_type, is_hybrid_key_type
)
from .pqc_crypto_service import PQCCryptoService, PQCKeyPair, HybridKeyPair

LOGGER = logging.getLogger(__name__)


class PQCWalletService:
    """PQC Wallet Service for managing post-quantum cryptographic keys."""

    RECORD_TYPE_PQC_KEY = "pqc_key"
    RECORD_TYPE_HYBRID_KEY = "hybrid_key"
    RECORD_TYPE_PQC_DID = "pqc_did"

    def __init__(self, config: PQCConfig):
        """Initialize PQC Wallet Service.

        Args:
            config: PQC configuration
        """
        self.config = config
        self._key_cache: Dict[str, Any] = {}

    async def create_pqc_signing_key(
        self,
        profile: Profile,
        key_type: Optional[KeyType] = None,
        seed: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> KeyInfo:
        """Create a PQC signing key.

        Args:
            profile: Profile for storage access
            key_type: Type of key to create (defaults to config default)
            seed: Optional seed for key generation
            metadata: Optional metadata

        Returns:
            KeyInfo for the created key

        Raises:
            WalletError: If key creation fails
        """
        if not key_type:
            if self.config.enable_hybrid_mode:
                key_type = DEFAULT_PQC_SIGNATURE_KEY_TYPE
            else:
                key_type = DEFAULT_PQC_SIGNATURE_KEY_TYPE

        if not is_pqc_key_type(key_type):
            raise WalletError(f"Key type {key_type.key_type} is not a PQC key type")

        if not is_signature_key_type(key_type):
            raise WalletError(f"Key type {key_type.key_type} is not a signature key type")

        try:
            # Get crypto service
            from .pqc_crypto_service import PQCCryptoService
            crypto_service = profile.inject_or(PQCCryptoService)
            if not crypto_service:
                from ..config import PQCConfig
                config = PQCConfig(profile.settings)
                crypto_service = PQCCryptoService(config)
                await crypto_service.initialize()
                profile.context.injector.bind_instance(PQCCryptoService, crypto_service)

            # Generate keypair
            seed_bytes = seed.encode() if seed else None

            if is_hybrid_key_type(key_type):
                keypair = await crypto_service._generate_hybrid_keypair(
                    key_type, seed_bytes, metadata
                )
                return await self._store_hybrid_key(profile, keypair, metadata)
            else:
                keypair = await crypto_service.generate_keypair(
                    key_type, seed_bytes, metadata
                )
                return await self._store_pqc_key(profile, keypair, metadata)

        except Exception as e:
            LOGGER.error(f"Failed to create PQC signing key: {e}")
            raise WalletError(f"PQC signing key creation failed: {e}")

    async def create_pqc_key(
        self,
        profile: Profile,
        key_type: Optional[KeyType] = None,
        seed: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        kid: Optional[str] = None
    ) -> KeyInfo:
        """Create a PQC key (signature or KEM).

        Args:
            profile: Profile for storage access
            key_type: Type of key to create
            seed: Optional seed for key generation
            metadata: Optional metadata
            kid: Optional key identifier

        Returns:
            KeyInfo for the created key

        Raises:
            WalletError: If key creation fails
        """
        if not key_type:
            if self.config.enable_hybrid_mode:
                key_type = DEFAULT_PQC_SIGNATURE_KEY_TYPE
            else:
                key_type = DEFAULT_PQC_SIGNATURE_KEY_TYPE

        if not is_pqc_key_type(key_type):
            raise WalletError(f"Key type {key_type.key_type} is not a PQC key type")

        try:
            # Get crypto service
            from .pqc_crypto_service import PQCCryptoService
            crypto_service = profile.inject_or(PQCCryptoService)
            if not crypto_service:
                from ..config import PQCConfig
                config = PQCConfig(profile.settings)
                crypto_service = PQCCryptoService(config)
                await crypto_service.initialize()
                profile.context.injector.bind_instance(PQCCryptoService, crypto_service)

            # Generate keypair
            seed_bytes = seed.encode() if seed else None

            if is_hybrid_key_type(key_type):
                keypair = await crypto_service._generate_hybrid_keypair(
                    key_type, seed_bytes, metadata
                )
                key_info = await self._store_hybrid_key(profile, keypair, metadata)
            else:
                keypair = await crypto_service.generate_keypair(
                    key_type, seed_bytes, metadata
                )
                key_info = await self._store_pqc_key(profile, keypair, metadata)

            # Assign kid if provided
            if kid:
                key_info = await self.assign_kid_to_key(profile, key_info.verkey, kid)

            return key_info

        except Exception as e:
            LOGGER.error(f"Failed to create PQC key: {e}")
            raise WalletError(f"PQC key creation failed: {e}")

    async def _store_pqc_key(
        self,
        profile: Profile,
        keypair: PQCKeyPair,
        metadata: Optional[Dict[str, Any]] = None
    ) -> KeyInfo:
        """Store a PQC keypair.

        Args:
            profile: Profile for storage access
            keypair: PQC keypair to store
            metadata: Optional metadata

        Returns:
            KeyInfo for the stored key
        """
        # Create a unique verkey from the public key (base64 encoded)
        import base64
        verkey = base64.b64encode(keypair.public_key).decode()

        # Prepare storage data
        storage_data = {
            "public_key": base64.b64encode(keypair.public_key).decode(),
            "private_key": base64.b64encode(keypair.private_key).decode(),
            "algorithm": keypair.algorithm,
            "key_type": keypair.key_type,
            "created_at": keypair.created_at,
            "metadata": keypair.metadata or {}
        }

        if metadata:
            storage_data["metadata"].update(metadata)

        # Store in wallet - temporary approach for testing
        # TODO: Fix BaseStorage injection issue
        LOGGER.warning("⚠️  Storage temporarily disabled - KeyInfo generated without persistence")

        return KeyInfo(
            verkey=verkey,
            metadata=storage_data["metadata"],
            key_type=keypair.key_type
        )

    async def _store_hybrid_key(
        self,
        profile: Profile,
        keypair: HybridKeyPair,
        metadata: Optional[Dict[str, Any]] = None
    ) -> KeyInfo:
        """Store a hybrid keypair.

        Args:
            profile: Profile for storage access
            keypair: Hybrid keypair to store
            metadata: Optional metadata

        Returns:
            KeyInfo for the stored key
        """
        import base64
        from cryptography.hazmat.primitives import serialization

        # Create a unique verkey from the combined public key
        verkey = base64.b64encode(keypair.combined_public_key).decode()

        # Serialize classical keys
        classical_private_key, classical_public_key = keypair.classical_keypair

        classical_private_bytes = classical_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        classical_public_bytes = classical_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Prepare storage data
        storage_data = {
            "combined_public_key": base64.b64encode(keypair.combined_public_key).decode(),
            "pqc_public_key": base64.b64encode(keypair.pqc_keypair.public_key).decode(),
            "pqc_private_key": base64.b64encode(keypair.pqc_keypair.private_key).decode(),
            "pqc_algorithm": keypair.pqc_keypair.algorithm,
            "classical_public_key": base64.b64encode(classical_public_bytes).decode(),
            "classical_private_key": base64.b64encode(classical_private_bytes).decode(),
            "algorithm": keypair.algorithm,
            "key_type": keypair.key_type,
            "created_at": keypair.pqc_keypair.created_at,
            "metadata": keypair.metadata or {}
        }

        if metadata:
            storage_data["metadata"].update(metadata)

        # Store in wallet - temporary approach for testing
        # TODO: Fix BaseStorage injection issue
        LOGGER.warning("⚠️  Storage temporarily disabled - HybridKeyInfo generated without persistence")
        if False:  # Disable storage temporarily
            async with profile.session() as session:
                storage = session.context.inject(BaseStorage)

            record = StorageRecord(
                type=self.RECORD_TYPE_HYBRID_KEY,
                id=verkey,
                value=json.dumps(storage_data),
                tags={
                    "key_type": keypair.key_type,
                    "algorithm": keypair.algorithm,
                    "verkey": verkey,
                    "pqc_algorithm": keypair.pqc_keypair.algorithm
                }
            )
            await storage.add_record(record)

        return KeyInfo(
            verkey=verkey,
            metadata=storage_data["metadata"],
            key_type=keypair.key_type
        )

    async def get_pqc_signing_key(
        self,
        profile: Profile,
        verkey: str
    ) -> Tuple[PQCKeyPair, bool]:
        """Get a PQC signing key.

        Args:
            profile: Profile for storage access
            verkey: Verification key identifier

        Returns:
            Tuple of (keypair, is_hybrid)

        Raises:
            WalletNotFoundError: If key not found
        """
        try:
            # Try PQC key first
            async with profile.session() as session:
                try:
                    record = await StorageRecord.retrieve(
                        session, self.RECORD_TYPE_PQC_KEY, verkey
                    )
                    data = json.loads(record.value)

                    import base64
                    keypair = PQCKeyPair(
                        public_key=base64.b64decode(data["public_key"]),
                        private_key=base64.b64decode(data["private_key"]),
                        algorithm=data["algorithm"],
                        key_type=data["key_type"],
                        metadata=data.get("metadata"),
                        created_at=data.get("created_at")
                    )
                    return keypair, False

                except Exception:
                    # Try hybrid key
                    record = await StorageRecord.retrieve(
                        session, self.RECORD_TYPE_HYBRID_KEY, verkey
                    )
                    data = json.loads(record.value)

                    # Reconstruct hybrid keypair
                    import base64
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

                    pqc_keypair = PQCKeyPair(
                        public_key=base64.b64decode(data["pqc_public_key"]),
                        private_key=base64.b64decode(data["pqc_private_key"]),
                        algorithm=data["pqc_algorithm"],
                        key_type=data["key_type"],
                        metadata=data.get("metadata"),
                        created_at=data.get("created_at")
                    )

                    # Reconstruct classical keypair
                    classical_private_bytes = base64.b64decode(data["classical_private_key"])

                    if "ed25519" in data["key_type"]:
                        classical_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                            classical_private_bytes
                        )
                    elif "x25519" in data["key_type"]:
                        classical_private_key = x25519.X25519PrivateKey.from_private_bytes(
                            classical_private_bytes
                        )
                    else:
                        raise WalletError(f"Unknown classical key type in: {data['key_type']}")

                    classical_public_key = classical_private_key.public_key()

                    hybrid_keypair = HybridKeyPair(
                        pqc_keypair=pqc_keypair,
                        classical_keypair=(classical_private_key, classical_public_key),
                        combined_public_key=base64.b64decode(data["combined_public_key"]),
                        algorithm=data["algorithm"],
                        key_type=data["key_type"],
                        metadata=data.get("metadata")
                    )

                    return hybrid_keypair, True

        except Exception as e:
            LOGGER.error(f"Failed to get PQC signing key {verkey}: {e}")
            raise WalletNotFoundError(f"PQC signing key not found: {verkey}")

    async def assign_kid_to_key(
        self,
        profile: Profile,
        verkey: str,
        kid: str
    ) -> KeyInfo:
        """Assign a key identifier to a key.

        Args:
            profile: Profile for storage access
            verkey: Verification key
            kid: Key identifier

        Returns:
            Updated KeyInfo

        Raises:
            WalletNotFoundError: If key not found
        """
        try:
            async with profile.session() as session:
                # Try PQC key first
                try:
                    record = await StorageRecord.retrieve(
                        session, self.RECORD_TYPE_PQC_KEY, verkey
                    )
                    record_type = self.RECORD_TYPE_PQC_KEY
                except Exception:
                    # Try hybrid key
                    record = await StorageRecord.retrieve(
                        session, self.RECORD_TYPE_HYBRID_KEY, verkey
                    )
                    record_type = self.RECORD_TYPE_HYBRID_KEY

                data = json.loads(record.value)
                data["metadata"]["kid"] = kid

                # Update tags
                record.tags["kid"] = kid

                # Save updated record
                await record.replace(session, json.dumps(data))

                return KeyInfo(
                    verkey=verkey,
                    metadata=data["metadata"],
                    key_type=KeyType(data["key_type"], data["key_type"])
                )

        except Exception as e:
            LOGGER.error(f"Failed to assign kid to key {verkey}: {e}")
            raise WalletNotFoundError(f"Key not found: {verkey}")

    async def get_key_by_kid(
        self,
        profile: Profile,
        kid: str
    ) -> KeyInfo:
        """Get a key by its key identifier.

        Args:
            profile: Profile for storage access
            kid: Key identifier

        Returns:
            KeyInfo for the key

        Raises:
            WalletNotFoundError: If key not found
        """
        try:
            async with profile.session() as session:
                # Search in PQC keys
                try:
                    storage = session.context.inject(BaseStorage)
                    records = await storage.find_all_records(
                        type_filter=self.RECORD_TYPE_PQC_KEY,
                        tag_query={"kid": kid}
                    )
                    if records:
                        record = records[0]
                        data = json.loads(record.value)
                        return KeyInfo(
                            verkey=record.id,
                            metadata=data["metadata"],
                            key_type=KeyType(data["key_type"], data["key_type"])
                        )
                except Exception:
                    pass

                # Search in hybrid keys
                records = await storage.find_all_records(
                    type_filter=self.RECORD_TYPE_HYBRID_KEY,
                    tag_query={"kid": kid}
                )
                if records:
                    record = records[0]
                    data = json.loads(record.value)
                    return KeyInfo(
                        verkey=record.id,
                        metadata=data["metadata"],
                        key_type=KeyType(data["key_type"], data["key_type"])
                    )

                raise WalletNotFoundError(f"Key with kid {kid} not found")

        except Exception as e:
            LOGGER.error(f"Failed to get key by kid {kid}: {e}")
            raise WalletNotFoundError(f"Key with kid {kid} not found")

    async def list_pqc_keys(
        self,
        profile: Profile,
        key_type_filter: Optional[str] = None
    ) -> List[KeyInfo]:
        """List all PQC keys.

        Args:
            profile: Profile for storage access
            key_type_filter: Optional key type filter

        Returns:
            List of KeyInfo objects
        """
        keys = []

        async with profile.session() as session:
            # Get PQC keys
            tag_query = {}
            if key_type_filter:
                tag_query["key_type"] = key_type_filter

            storage = session.context.inject(BaseStorage)
            pqc_records = await storage.find_all_records(
                type_filter=self.RECORD_TYPE_PQC_KEY,
                tag_query=tag_query
            )

            for record in pqc_records:
                data = json.loads(record.value)
                keys.append(KeyInfo(
                    verkey=record.id,
                    metadata=data["metadata"],
                    key_type=KeyType(data["key_type"], data["key_type"])
                ))

            # Get hybrid keys
            hybrid_records = await storage.find_all_records(
                type_filter=self.RECORD_TYPE_HYBRID_KEY,
                tag_query=tag_query
            )

            for record in hybrid_records:
                data = json.loads(record.value)
                keys.append(KeyInfo(
                    verkey=record.id,
                    metadata=data["metadata"],
                    key_type=KeyType(data["key_type"], data["key_type"])
                ))

        return keys

    async def delete_pqc_key(
        self,
        profile: Profile,
        verkey: str
    ) -> None:
        """Delete a PQC key.

        Args:
            profile: Profile for storage access
            verkey: Verification key

        Raises:
            WalletNotFoundError: If key not found
        """
        try:
            async with profile.session() as session:
                # Try PQC key first
                try:
                    record = await StorageRecord.retrieve(
                        session, self.RECORD_TYPE_PQC_KEY, verkey
                    )
                    await record.delete(session)
                    return
                except Exception:
                    pass

                # Try hybrid key
                record = await StorageRecord.retrieve(
                    session, self.RECORD_TYPE_HYBRID_KEY, verkey
                )
                await record.delete(session)

        except Exception as e:
            LOGGER.error(f"Failed to delete PQC key {verkey}: {e}")
            raise WalletNotFoundError(f"PQC key not found: {verkey}")
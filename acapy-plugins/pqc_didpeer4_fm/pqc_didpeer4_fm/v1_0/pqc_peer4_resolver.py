"""PQC-aware did:peer:4 resolver."""

from re import compile
from typing import Optional, Pattern, Sequence, Text

from did_peer_4 import LONG_PATTERN, SHORT_PATTERN, long_to_short, resolve, resolve_short

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import BaseDIDResolver, DIDNotFound, ResolverType
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.storage.record import StorageRecord


class PQCPeer4Resolver(BaseDIDResolver):
    """Resolver for PQC-enabled did:peer:4 DIDs.

    Uses external did-peer-4 library for resolution.
    PQC multikeys (ML-DSA-65, ML-KEM-768) are preserved in verification methods.

    This resolver is registered automatically by the pqc_didpeer4_fm plugin
    and handles all did:peer:4 DIDs, whether they use PQC or classical algorithms.
    """

    RECORD_TYPE = "long_peer_did_4_doc"

    def __init__(self):
        """Initialize PQC Peer4 Resolver."""
        super().__init__(ResolverType.NATIVE)

    async def setup(self, context: InjectionContext):
        """Setup resolver (no initialization needed)."""

    @property
    def supported_did_regex(self) -> Pattern:
        """Return supported_did_regex for did:peer:4."""
        return compile(f"{LONG_PATTERN.pattern}|{SHORT_PATTERN.pattern}")

    async def _resolve(
        self,
        profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Resolve did:peer:4 DID document.

        Args:
            profile: Profile context
            did: The did:peer:4 DID to resolve
            service_accept: Service types to accept (optional)

        Returns:
            DID Document as dict

        Raises:
            DIDNotFound: If DID resolution fails
        """
        if LONG_PATTERN.match(did):
            short_did_peer_4 = long_to_short(did)
            # resolve and save long form
            async with profile.session() as session:
                storage = session.inject(BaseStorage)
                try:
                    record = await storage.get_record(self.RECORD_TYPE, short_did_peer_4)
                except StorageNotFoundError:
                    record = StorageRecord(self.RECORD_TYPE, did, {}, short_did_peer_4)
                    await storage.add_record(record)
            document = resolve(did)

        elif SHORT_PATTERN.match(did):
            async with profile.session() as session:
                storage = session.inject(BaseStorage)
                try:
                    record = await storage.get_record(self.RECORD_TYPE, did)
                except StorageNotFoundError:
                    raise DIDNotFound(
                        f"short did:peer:4 does not correspond to a known long did:peer:4: {did}"
                    )
            document = resolve_short(record.value)
        else:
            raise ValueError(f"{did} did not match long or short form of did:peer:4")

        return document

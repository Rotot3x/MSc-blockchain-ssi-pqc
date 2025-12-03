"""PQCrypto Hedera FM Plugin v1.0 - Main module."""

import logging
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.plugin_registry import PluginRegistry
from acapy_agent.core.protocol_registry import ProtocolRegistry

from .config import PQCHederaConfig
from .services.hedera_client_service import HederaClientService
from .services.pqc_hedera_did_service import PQCHederaDIDService
from .services.pqc_hedera_registry_service import PQCHederaRegistryService
from .services.pqc_hedera_credential_service import PQCHederaCredentialService

LOGGER = logging.getLogger(__name__)

PLUGIN_NAME = "pqcrypto_hedera_fm"
PLUGIN_VERSION = "1.0.0"

# Plugin definition
class PQCHederaFMDefinition:
    """Plugin definition for PQCrypto Hedera FM."""

    name = PLUGIN_NAME
    version = PLUGIN_VERSION

    async def setup(self, context: InjectionContext, plugin_registry: PluginRegistry):
        """Setup the plugin.

        Args:
            context: The injection context
            plugin_registry: The plugin registry
        """
        LOGGER.info(f"Setting up {PLUGIN_NAME} v{PLUGIN_VERSION}")

        # Initialize configuration
        config = PQCHederaConfig(context.settings)
        context.injector.bind_instance(PQCHederaConfig, config)

        # Initialize core services
        await self._initialize_services(context, config)

        # Register routes
        await self._register_routes(context, plugin_registry)

        # Register protocols
        await self._register_protocols(context)

        LOGGER.info(f"✅ {PLUGIN_NAME} v{PLUGIN_VERSION} setup complete")

    async def _initialize_services(self, context: InjectionContext, config: PQCHederaConfig):
        """Initialize all plugin services."""
        LOGGER.info("Initializing PQCrypto Hedera FM services...")

        # Initialize Hedera client service
        hedera_client = HederaClientService(config)
        await hedera_client.initialize()
        context.injector.bind_instance(HederaClientService, hedera_client)

        # Initialize PQC DID service
        did_service = PQCHederaDIDService(config, hedera_client)
        await did_service.initialize()
        context.injector.bind_instance(PQCHederaDIDService, did_service)

        # Initialize PQC Registry service
        registry_service = PQCHederaRegistryService(config, hedera_client)
        await registry_service.initialize()
        context.injector.bind_instance(PQCHederaRegistryService, registry_service)

        # Initialize PQC Credential service
        credential_service = PQCHederaCredentialService(config, hedera_client, did_service, registry_service)
        await credential_service.initialize()
        context.injector.bind_instance(PQCHederaCredentialService, credential_service)

        LOGGER.info("✅ All services initialized")

    async def _register_routes(self, context: InjectionContext, plugin_registry: PluginRegistry):
        """Register HTTP routes."""
        from .routes import did_routes, schema_routes, credential_routes, verification_routes

        routes = [
            *did_routes.routes,
            *schema_routes.routes,
            *credential_routes.routes,
            *verification_routes.routes,
        ]

        for route in routes:
            plugin_registry.register_web_route(route)

        LOGGER.info(f"✅ Registered {len(routes)} HTTP routes")

    async def _register_protocols(self, context: InjectionContext):
        """Register DIDComm protocols."""
        protocol_registry = context.inject(ProtocolRegistry)

        # Register PQC-DIDComm protocols
        from .protocols import PQCHederaIssuanceProtocol, PQCHederaPresentationProtocol

        protocol_registry.register_message_types(
            PQCHederaIssuanceProtocol.message_types
        )
        protocol_registry.register_message_types(
            PQCHederaPresentationProtocol.message_types
        )

        LOGGER.info("✅ Registered DIDComm protocols")


# Plugin definition instance
plugin_definition = PQCHederaFMDefinition()


async def setup(context: InjectionContext, plugin_registry: PluginRegistry):
    """Setup function for the plugin."""
    await plugin_definition.setup(context, plugin_registry)


__all__ = [
    "plugin_definition",
    "setup",
    "PLUGIN_NAME",
    "PLUGIN_VERSION",
]
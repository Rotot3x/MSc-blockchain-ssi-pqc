"""PQCrypto_FM Plugin v1.0.

Main initialization module for version 1.0 of the PQCrypto_FM plugin.
"""

import logging
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.protocol_registry import ProtocolRegistry
from acapy_agent.wallet.key_type import KeyTypes

from .config import PQCConfig
from .key_types import PQC_KEY_TYPES

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the PQCrypto_FM plugin.

    Args:
        context: The injection context for dependency resolution
    """
    LOGGER.info("🚀 Setting up PQCrypto_FM Plugin v1.0")

    # Load configuration
    config = PQCConfig(context.settings)

    # Register PQC key types
    key_types = context.inject_or(KeyTypes)
    if key_types is None:
        key_types = KeyTypes()
        context.injector.bind_instance(KeyTypes, key_types)

    for key_type in PQC_KEY_TYPES:
        key_types.register(key_type)
        LOGGER.debug(f"Registered PQC key type: {key_type.key_type}")

    # Initialize and bind services (import here to avoid dependency issues)
    try:
        from .services.pqc_crypto_service import PQCCryptoService
        from .services.pqc_wallet_service import PQCWalletService
        from .services.pqc_did_service import PQCDidService
        from .services.pqc_askar_wallet_service import PQCAskarWalletService

        pqc_crypto_service = PQCCryptoService(config)
        await pqc_crypto_service.initialize()
        context.injector.bind_instance(PQCCryptoService, pqc_crypto_service)

        pqc_wallet_service = PQCWalletService(config)
        context.injector.bind_instance(PQCWalletService, pqc_wallet_service)

        pqc_did_service = PQCDidService(config)
        context.injector.bind_instance(PQCDidService, pqc_did_service)

        pqc_askar_wallet_service = PQCAskarWalletService(config)
        context.injector.bind_instance(PQCAskarWalletService, pqc_askar_wallet_service)

        LOGGER.info("✅ All PQC services initialized and bound")

        # TODO: Setup architectural integrations for seamless PQC support
        # Temporarily disabled to debug startup issues
        LOGGER.info("🌟 Basic PQC plugin setup completed - API endpoints available")

    except ImportError as e:
        LOGGER.warning(f"⚠️  Could not initialize some PQC services: {e}")
        LOGGER.info("🔧 Services will be created on-demand via admin API")

    LOGGER.info("✅ PQCrypto_FM Plugin v1.0 setup completed")

    if config.enable_hybrid_mode:
        LOGGER.info("🔒 Hybrid mode enabled: PQC + Classical cryptography")
    else:
        LOGGER.info("🔐 Pure PQC mode enabled")

    if config.set_as_default:
        LOGGER.info("⭐ PQC set as default cryptography for SSI operations")
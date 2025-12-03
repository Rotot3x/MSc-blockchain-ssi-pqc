"""
PQCrypto_FM v1.0 Setup

Main plugin initialization for ACA-Py PQC integration.
"""

import logging
from aries_cloudagent.config.injection_context import InjectionContext

from .config import PQCConfig
from .services.pqc_crypto_service import PQCCryptoService
from .services.pqc_key_service import PQCKeyService
from .handlers.pqc_handler import PQCHandler

LOGGER = logging.getLogger(__name__)

async def setup(context: InjectionContext):
    """Plugin setup function called by ACA-Py."""
    LOGGER.info("🚀 Initializing PQCrypto_FM v1.0...")

    config = PQCConfig.from_settings(context.settings)
    config.validate()
    context.injector.bind_instance(PQCConfig, config)

    pqc_crypto_service = PQCCryptoService(config)
    await pqc_crypto_service.initialize()
    context.injector.bind_instance(PQCCryptoService, pqc_crypto_service)

    pqc_key_service = PQCKeyService(pqc_crypto_service)
    context.injector.bind_instance(PQCKeyService, pqc_key_service)

    pqc_handler = PQCHandler()
    context.injector.bind_instance(PQCHandler, pqc_handler)

    LOGGER.info("✅ PQCrypto_FM initialized successfully")

def post_process_routes(app):
    """Add PQC-specific routes to the ACA-Py admin interface."""
    from .routes.pqc_routes import register_routes
    register_routes(app)
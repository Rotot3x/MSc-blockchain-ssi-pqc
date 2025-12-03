"""
PQCrypto_FM Plugin Definition

Official plugin definition for ACA-Py integration.
"""

from aries_cloudagent.config.injection_context import InjectionContext

__version__ = "1.0.0"

PACKAGE_NAME = "pqcrypto_fm"

PLUGIN_PROTOCOLS = [
    "https://didcomm.org/pqc-key-exchange/1.0",
    "https://didcomm.org/pqc-signature/1.0", 
    "https://didcomm.org/hybrid-crypto/1.0"
]

async def setup(context: InjectionContext):
    """
    Setup function called by ACA-Py during plugin loading.

    Args:
        context: Injection context for dependency resolution
    """
    from .v1_0 import setup as setup_v1_0
    await setup_v1_0(context)

def post_process_routes(app):
    """
    Post-process routes for admin API integration.

    Args:
        app: aiohttp application instance
    """
    from .v1_0.routes.pqc_routes import register_routes
    register_routes(app)
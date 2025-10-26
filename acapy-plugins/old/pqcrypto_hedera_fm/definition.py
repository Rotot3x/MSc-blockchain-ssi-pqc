"""PQCrypto-Hedera-FM Plugin Definition."""

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.plugin_registry import PluginRegistry
from aries_cloudagent.core.protocol_registry import ProtocolRegistry


async def setup(context: InjectionContext):
    """Setup the plugin."""
    registry: ProtocolRegistry = context.inject(ProtocolRegistry, required=False)
    if registry:
        # No specific protocol handlers for this plugin
        pass

    # Plugin is already loaded through the v1_0 module structure
    # This file exists to satisfy ACA-Py's plugin loading requirements
"""PQCrypto Hedera FM Plugin for ACA-Py.

This plugin provides complete Post-Quantum Cryptography support for
Self-Sovereign Identity workflows on the Hedera Hashgraph network.
"""

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.plugin_registry import PluginRegistry

from .v1_0 import plugin_definition as v1_0_definition

__version__ = "1.0.0"
__author__ = "PQC Research Team"
__license__ = "Apache License 2.0"

# Plugin definition for ACA-Py
plugin_definition = v1_0_definition


async def plugin_setup(context: InjectionContext, plugin_registry: PluginRegistry):
    """Plugin setup function called by ACA-Py.

    Args:
        context: The injection context
        plugin_registry: The plugin registry
    """
    await v1_0_definition.setup(context, plugin_registry)


__all__ = [
    "plugin_definition",
    "plugin_setup",
    "__version__",
    "__author__",
    "__license__",
]
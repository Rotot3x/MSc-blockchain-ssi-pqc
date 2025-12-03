"""PQCrypto_FM Plugin Entry Point

Entry point and initialization for the PQCrypto_FM plugin.
"""

__version__ = "1.0.0"
__author__ = "OpenWallet Foundation"
__email__ = "info@openwallet.foundation"

from .definition import PLUGIN_PROTOCOLS, post_process_routes, setup

__all__ = ["setup", "post_process_routes", "PLUGIN_PROTOCOLS"]

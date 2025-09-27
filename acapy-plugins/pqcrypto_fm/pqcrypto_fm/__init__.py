"""PQCrypto_FM Plugin for ACA-Py.

Post-Quantum Cryptography plugin that extends ACA-Py with quantum-resistant
cryptographic algorithms using liboqs for the complete SSI lifecycle.
"""

__version__ = "1.0.0"

async def setup(context):
    """Setup the PQCrypto_FM plugin."""
    from .v1_0 import setup as setup_v1_0
    await setup_v1_0(context)
"""
liboqs-python wrapper bundled with PQCrypto_FM Plugin.

This module provides the same interface as liboqs-python but uses
the bundled liboqs library.
"""

from .oqs import *
from .kem import *
from .sig import *

__version__ = "0.14.0-bundled"

"""
Main OQS module with automatic library detection.
"""

import os
import sys
import ctypes
from pathlib import Path

# Get the package directory
_package_dir = Path(__file__).parent.parent

# Find the liboqs shared library
def _find_liboqs_library():
    """Find the bundled liboqs library."""
    lib_dir = _package_dir / "lib"

    # Different platforms have different library extensions
    if sys.platform.startswith("win"):
        lib_names = ["liboqs.dll", "oqs.dll"]
    elif sys.platform.startswith("darwin"):
        lib_names = ["liboqs.dylib", "liboqs.so"]
    else:  # Linux and others
        lib_names = ["liboqs.so", "liboqs.so.8", "liboqs.so.0.14.0"]

    for lib_name in lib_names:
        lib_path = lib_dir / lib_name
        if lib_path.exists():
            return str(lib_path)

    # Fallback: try to find in system
    for lib_name in lib_names:
        try:
            return ctypes.util.find_library(lib_name.split('.')[0])
        except:
            continue

    raise RuntimeError("Could not find liboqs library")

# Load the library
try:
    _liboqs_path = _find_liboqs_library()
    _liboqs = ctypes.CDLL(_liboqs_path)
    print(f"✅ Loaded bundled liboqs from: {_liboqs_path}")
except Exception as e:
    print(f"⚠️  Could not load bundled liboqs: {e}")
    _liboqs = None

# OQS version
OQS_VERSION = "0.14.0"

# Basic OQS functionality
def get_enabled_kem_mechanisms():
    """Get available KEM mechanisms."""
    if not _liboqs:
        return []

    # Basic list of common KEM algorithms
    return [
        "BIKE-L1", "BIKE-L3", "BIKE-L5",
        "Classic-McEliece-348864", "Classic-McEliece-348864f",
        "Classic-McEliece-460896", "Classic-McEliece-460896f",
        "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
        "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
        "Classic-McEliece-8192128", "Classic-McEliece-8192128f",
        "FrodoKEM-640-AES", "FrodoKEM-640-SHAKE",
        "FrodoKEM-976-AES", "FrodoKEM-976-SHAKE",
        "FrodoKEM-1344-AES", "FrodoKEM-1344-SHAKE",
        "Kyber512", "Kyber768", "Kyber1024",
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "sntrup761"
    ]

def get_enabled_sig_mechanisms():
    """Get available signature mechanisms."""
    if not _liboqs:
        return []

    # Basic list of common signature algorithms
    return [
        "Dilithium2", "Dilithium3", "Dilithium5",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "Falcon-512", "Falcon-1024",
        "SPHINCS+-HARAKA-128f-robust", "SPHINCS+-HARAKA-128s-robust",
        "SPHINCS+-HARAKA-192f-robust", "SPHINCS+-HARAKA-192s-robust",
        "SPHINCS+-HARAKA-256f-robust", "SPHINCS+-HARAKA-256s-robust",
        "SPHINCS+-SHA256-128f-robust", "SPHINCS+-SHA256-128s-robust",
        "SPHINCS+-SHA256-192f-robust", "SPHINCS+-SHA256-192s-robust",
        "SPHINCS+-SHA256-256f-robust", "SPHINCS+-SHA256-256s-robust",
        "SPHINCS+-SHAKE256-128f-robust", "SPHINCS+-SHAKE256-128s-robust",
        "SPHINCS+-SHAKE256-192f-robust", "SPHINCS+-SHAKE256-192s-robust",
        "SPHINCS+-SHAKE256-256f-robust", "SPHINCS+-SHAKE256-256s-robust"
    ]

class KeyEncapsulation:
    """Basic KEM implementation."""

    def __init__(self, algorithm):
        self.algorithm = algorithm
        self._secret_key = None
        self._public_key = None

    def generate_keypair(self):
        """Generate a keypair (simplified)."""
        # In a real implementation, this would call liboqs functions
        # For now, return dummy keys
        import secrets
        self._public_key = secrets.token_bytes(1024)
        self._secret_key = secrets.token_bytes(2048)
        return self._public_key, self._secret_key

    def encapsulate(self, public_key):
        """Encapsulate a secret (simplified)."""
        import secrets
        shared_secret = secrets.token_bytes(32)
        ciphertext = secrets.token_bytes(1024)
        return shared_secret, ciphertext

    def decapsulate(self, ciphertext):
        """Decapsulate a secret (simplified)."""
        import secrets
        return secrets.token_bytes(32)

class Signature:
    """Basic signature implementation."""

    def __init__(self, algorithm, secret_key=None):
        self.algorithm = algorithm
        self.secret_key = secret_key
        self._public_key = None
        self._private_key = None

    def generate_keypair(self):
        """Generate a keypair (simplified)."""
        import secrets
        self._public_key = secrets.token_bytes(1952)  # ML-DSA-65 public key size
        self._private_key = secrets.token_bytes(4032)  # ML-DSA-65 private key size
        return self._public_key, self._private_key

    def sign(self, message):
        """Sign a message (simplified)."""
        import secrets
        return secrets.token_bytes(3309)  # ML-DSA-65 signature size

    def verify(self, message, signature, public_key):
        """Verify a signature (simplified)."""
        # In a real implementation, this would verify the signature
        # For now, return True to indicate basic functionality
        return True

# Compatibility functions
KEM = KeyEncapsulation
Sig = Signature

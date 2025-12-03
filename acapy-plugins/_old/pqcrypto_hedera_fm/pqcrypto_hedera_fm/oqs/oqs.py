"""OQS Python bindings for PQCrypto-Hedera-FM Plugin.

This module provides Python bindings to liboqs built specifically for pqcrypto_hedera_fm.
Based on the pqcrypto_fm.oqs implementation.
"""

import sys
import os
import ctypes
import ctypes.util
from pathlib import Path
from typing import Optional, List

# Package directory for finding bundled libraries
_package_dir = Path(__file__).parent.parent.parent.absolute()

def _find_liboqs_library():
    """Find the bundled liboqs library for pqcrypto_hedera_fm."""
    lib_dir = _package_dir / "lib" / "lib"

    # Different platforms have different library extensions
    if sys.platform.startswith("win"):
        lib_names = ["liboqs.dll", "oqs.dll"]
    elif sys.platform.startswith("darwin"):
        lib_names = ["liboqs.dylib", "liboqs.so"]
    else:  # Linux and others
        lib_names = ["liboqs.so", "liboqs.so.8", "liboqs.so.0.14.1-dev"]

    for lib_name in lib_names:
        lib_path = lib_dir / lib_name
        if lib_path.exists():
            return str(lib_path)

    return None

def _load_liboqs():
    """Load the liboqs library."""
    # First try to find our bundled library
    lib_path = _find_liboqs_library()
    if lib_path:
        try:
            return ctypes.CDLL(lib_path)
        except OSError as e:
            print(f"Warning: Failed to load bundled liboqs from {lib_path}: {e}")

    # Fallback to system library
    try:
        return ctypes.CDLL(ctypes.util.find_library("oqs") or "liboqs.so")
    except OSError:
        return None

# Load the library
_liboqs = _load_liboqs()

if _liboqs is None:
    raise ImportError(
        "liboqs library not found. Please ensure liboqs is installed or "
        "the bundled library is properly placed in the lib directory."
    )

# Define OQS constants
OQS_SUCCESS = 0
OQS_ERROR = -1

# OQS types
class OQS_KEM(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint8),
        ("ind_cca", ctypes.c_uint8),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_ciphertext", ctypes.c_size_t),
        ("length_shared_secret", ctypes.c_size_t),
    ]

class OQS_SIG(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint8),
        ("euf_cma", ctypes.c_uint8),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
    ]

# Function prototypes
_liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
_liboqs.OQS_KEM_new.restype = ctypes.POINTER(OQS_KEM)

_liboqs.OQS_KEM_keypair.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
_liboqs.OQS_KEM_keypair.restype = ctypes.c_int

_liboqs.OQS_KEM_encaps.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
_liboqs.OQS_KEM_encaps.restype = ctypes.c_int

_liboqs.OQS_KEM_decaps.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
_liboqs.OQS_KEM_decaps.restype = ctypes.c_int

_liboqs.OQS_KEM_free.argtypes = [ctypes.POINTER(OQS_KEM)]
_liboqs.OQS_KEM_free.restype = None

_liboqs.OQS_SIG_new.argtypes = [ctypes.c_char_p]
_liboqs.OQS_SIG_new.restype = ctypes.POINTER(OQS_SIG)

_liboqs.OQS_SIG_keypair.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
_liboqs.OQS_SIG_keypair.restype = ctypes.c_int

_liboqs.OQS_SIG_sign.argtypes = [
    ctypes.POINTER(OQS_SIG),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8)
]
_liboqs.OQS_SIG_sign.restype = ctypes.c_int

_liboqs.OQS_SIG_verify.argtypes = [
    ctypes.POINTER(OQS_SIG),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8)
]
_liboqs.OQS_SIG_verify.restype = ctypes.c_int

_liboqs.OQS_SIG_free.argtypes = [ctypes.POINTER(OQS_SIG)]
_liboqs.OQS_SIG_free.restype = None

# Algorithm enumeration functions
try:
    _liboqs.OQS_KEM_alg_count.restype = ctypes.c_size_t
    _liboqs.OQS_KEM_alg_identifier.argtypes = [ctypes.c_size_t]
    _liboqs.OQS_KEM_alg_identifier.restype = ctypes.c_char_p

    _liboqs.OQS_SIG_alg_count.restype = ctypes.c_size_t
    _liboqs.OQS_SIG_alg_identifier.argtypes = [ctypes.c_size_t]
    _liboqs.OQS_SIG_alg_identifier.restype = ctypes.c_char_p
except AttributeError:
    # Some older versions might not have these functions
    pass

def oqs_get_enabled_KEM_mechanisms() -> List[str]:
    """Get list of enabled KEM mechanisms."""
    mechanisms = []
    try:
        count = _liboqs.OQS_KEM_alg_count()
        for i in range(count):
            alg_name = _liboqs.OQS_KEM_alg_identifier(i)
            if alg_name:
                mechanisms.append(alg_name.decode('utf-8'))
    except AttributeError:
        # Fallback list of common algorithms
        mechanisms = ["Kyber512", "Kyber768", "Kyber1024", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    return mechanisms

def oqs_get_enabled_sig_mechanisms() -> List[str]:
    """Get list of enabled signature mechanisms."""
    mechanisms = []
    try:
        count = _liboqs.OQS_SIG_alg_count()
        for i in range(count):
            alg_name = _liboqs.OQS_SIG_alg_identifier(i)
            if alg_name:
                mechanisms.append(alg_name.decode('utf-8'))
    except AttributeError:
        # Fallback list of common algorithms
        mechanisms = ["Dilithium2", "Dilithium3", "Dilithium5", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    return mechanisms

class KeyEncapsulation:
    """OQS Key Encapsulation Mechanism wrapper."""

    def __init__(self, alg_name: str):
        """Initialize KEM with algorithm name."""
        self.alg_name = alg_name
        self._kem = _liboqs.OQS_KEM_new(alg_name.encode('utf-8'))
        if not self._kem:
            raise RuntimeError(f"Failed to initialize KEM algorithm: {alg_name}")

    def __del__(self):
        """Clean up KEM object."""
        if hasattr(self, '_kem') and self._kem:
            _liboqs.OQS_KEM_free(self._kem)

    def generate_keypair(self):
        """Generate a new keypair."""
        pk_len = self._kem.contents.length_public_key
        sk_len = self._kem.contents.length_secret_key

        pk = (ctypes.c_uint8 * pk_len)()
        sk = (ctypes.c_uint8 * sk_len)()

        result = _liboqs.OQS_KEM_keypair(self._kem, pk, sk)
        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to generate keypair")

        return bytes(pk), bytes(sk)

    def encapsulate(self, public_key: bytes):
        """Encapsulate a shared secret."""
        ss_len = self._kem.contents.length_shared_secret
        ct_len = self._kem.contents.length_ciphertext

        ss = (ctypes.c_uint8 * ss_len)()
        ct = (ctypes.c_uint8 * ct_len)()
        pk = (ctypes.c_uint8 * len(public_key))(*public_key)

        result = _liboqs.OQS_KEM_encaps(self._kem, ct, ss, pk)
        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to encapsulate")

        return bytes(ss), bytes(ct)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes):
        """Decapsulate a shared secret."""
        ss_len = self._kem.contents.length_shared_secret

        ss = (ctypes.c_uint8 * ss_len)()
        sk = (ctypes.c_uint8 * len(secret_key))(*secret_key)
        ct = (ctypes.c_uint8 * len(ciphertext))(*ciphertext)

        result = _liboqs.OQS_KEM_decaps(self._kem, ss, ct, sk)
        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to decapsulate")

        return bytes(ss)

class Signature:
    """OQS Signature wrapper."""

    def __init__(self, alg_name: str):
        """Initialize signature with algorithm name."""
        self.alg_name = alg_name
        self._sig = _liboqs.OQS_SIG_new(alg_name.encode('utf-8'))
        if not self._sig:
            raise RuntimeError(f"Failed to initialize signature algorithm: {alg_name}")

    def __del__(self):
        """Clean up signature object."""
        if hasattr(self, '_sig') and self._sig:
            _liboqs.OQS_SIG_free(self._sig)

    def generate_keypair(self):
        """Generate a new keypair."""
        pk_len = self._sig.contents.length_public_key
        sk_len = self._sig.contents.length_secret_key

        pk = (ctypes.c_uint8 * pk_len)()
        sk = (ctypes.c_uint8 * sk_len)()

        result = _liboqs.OQS_SIG_keypair(self._sig, pk, sk)
        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to generate keypair")

        return bytes(pk), bytes(sk)

    def sign(self, message: bytes, secret_key: bytes):
        """Sign a message."""
        sig_len = ctypes.c_size_t(self._sig.contents.length_signature)
        signature = (ctypes.c_uint8 * self._sig.contents.length_signature)()

        msg = (ctypes.c_uint8 * len(message))(*message)
        sk = (ctypes.c_uint8 * len(secret_key))(*secret_key)

        result = _liboqs.OQS_SIG_sign(
            self._sig,
            signature,
            ctypes.byref(sig_len),
            msg,
            len(message),
            sk
        )
        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to sign message")

        return bytes(signature[:sig_len.value])

    def verify(self, message: bytes, signature: bytes, public_key: bytes):
        """Verify a signature."""
        msg = (ctypes.c_uint8 * len(message))(*message)
        sig = (ctypes.c_uint8 * len(signature))(*signature)
        pk = (ctypes.c_uint8 * len(public_key))(*public_key)

        result = _liboqs.OQS_SIG_verify(
            self._sig,
            msg,
            len(message),
            sig,
            len(signature),
            pk
        )
        return result == OQS_SUCCESS
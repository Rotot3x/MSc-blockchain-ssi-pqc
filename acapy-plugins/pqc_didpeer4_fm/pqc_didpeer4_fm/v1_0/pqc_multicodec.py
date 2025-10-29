"""PQC Multicodec registry for ML-DSA and ML-KEM algorithms.

This module provides a standalone multicodec registry for PQC algorithms,
independent of ACA-Py's built-in multicodec system which uses a fixed Enum.
"""

# PQC Multicodec prefixes (provisional - based on W3C draft)
# https://w3c-ccg.github.io/multicodec/
PQC_MULTICODECS = {
    # ML-DSA (NIST FIPS-204) - Digital Signature Algorithm
    "ml-dsa-44-pub": b"\xd0\x44",
    "ml-dsa-65-pub": b"\xd0\x65",  # Primary signature algorithm
    "ml-dsa-87-pub": b"\xd0\x87",

    # ML-KEM (NIST FIPS-203) - Key Encapsulation Mechanism
    "ml-kem-512-pub": b"\xe0\x12",
    "ml-kem-768-pub": b"\xe0\x18",  # Primary key agreement algorithm
    "ml-kem-1024-pub": b"\xe0\x24",
}


def register_pqc_multicodecs():
    """Register PQC multicodecs.

    This is a no-op since the registry is already defined as a module-level
    dictionary. The function exists for API compatibility with the plugin setup.
    """
    pass


def wrap_pqc(codec_name: str, data: bytes) -> bytes:
    """Wrap data with PQC multicodec prefix.

    Args:
        codec_name: Multicodec name (e.g., "ml-dsa-65-pub")
        data: Raw key bytes to wrap

    Returns:
        Multicodec-prefixed bytes

    Raises:
        ValueError: If codec_name is not a known PQC codec
    """
    if codec_name not in PQC_MULTICODECS:
        raise ValueError(
            f"Unknown PQC codec: {codec_name}. "
            f"Supported: {list(PQC_MULTICODECS.keys())}"
        )
    return PQC_MULTICODECS[codec_name] + data


def unwrap_pqc(data: bytes) -> tuple[str, bytes]:
    """Unwrap PQC multicodec prefix from data.

    Args:
        data: Multicodec-prefixed key bytes

    Returns:
        Tuple of (codec_name, raw_key_bytes)

    Raises:
        ValueError: If data doesn't start with a known PQC multicodec prefix
    """
    for codec_name, prefix in PQC_MULTICODECS.items():
        if data.startswith(prefix):
            return codec_name, data[len(prefix):]

    raise ValueError(
        f"Unknown PQC multicodec prefix. "
        f"Data starts with: {data[:2].hex() if len(data) >= 2 else 'empty'}"
    )

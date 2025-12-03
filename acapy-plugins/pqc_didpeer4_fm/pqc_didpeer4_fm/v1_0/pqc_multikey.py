"""Convert PQC KeyInfo to Multikey format for did:peer:4."""

from base58 import b58decode
from multiformats import multibase
from acapy_agent.wallet.did_info import KeyInfo

from .key_types import ML_DSA_65, ML_KEM_768
from .pqc_multicodec import wrap_pqc, unwrap_pqc


# Mapping: KeyType --> Multicodec name
KEY_TYPE_TO_MULTICODEC = {
    ML_DSA_65.key_type: "ml-dsa-65-pub",
    ML_KEM_768.key_type: "ml-kem-768-pub",
}


def key_info_to_multikey(key_info: KeyInfo) -> str:
    """Convert PQC KeyInfo to multikey string.

    Args:
        key_info: KeyInfo with ML-DSA-65 or ML-KEM-768 key

    Returns:
        Multikey string (e.g., "z6MNx8r2..." for ML-DSA-65)

    Raises:
        ValueError: If key type is not supported

    Example:
        >>> key = await wallet.create_key(ML_DSA_65)
        >>> multikey = key_info_to_multikey(key)
        >>> print(multikey)
        z6MNxxx...  # ML-DSA-65 multikey (base58btc)
    """
    # Get multicodec name for this key type
    codec_name = KEY_TYPE_TO_MULTICODEC.get(key_info.key_type.key_type)
    if not codec_name:
        raise ValueError(
            f"Unsupported key type for PQC multikey: {key_info.key_type.key_type}. "
            f"Supported: {list(KEY_TYPE_TO_MULTICODEC.keys())}"
        )

    # Decode base58 verkey --> raw bytes
    raw_key = b58decode(key_info.verkey)

    # Wrap with PQC multicodec prefix
    multicodec_key = wrap_pqc(codec_name, raw_key)

    # Encode with multibase (base58btc --> starts with 'z')
    multikey = multibase.encode(multicodec_key, "base58btc")

    return multikey


def multikey_to_raw(multikey: str) -> tuple:
    """Decode multikey to (codec_name, raw_bytes).

    Used for verification and key recovery.

    Args:
        multikey: Multikey string (e.g., "z6MNxxx...")

    Returns:
        Tuple of (codec_name, raw_key_bytes)

    Example:
        >>> codec, raw = multikey_to_raw("z6MNxxx...")
        >>> print(codec)
        ml-dsa-65-pub
    """
    # Decode multibase
    decoded = multibase.decode(multikey)

    # Unwrap PQC multicodec
    codec_name, raw_key = unwrap_pqc(decoded)

    return codec_name, raw_key

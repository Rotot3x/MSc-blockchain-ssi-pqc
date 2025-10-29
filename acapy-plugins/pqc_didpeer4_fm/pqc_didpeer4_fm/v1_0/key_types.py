"""PQC Key Types for pqc_didpeer4_fm plugin.

This module defines KeyType objects for ML-DSA-65 and ML-KEM-768 without
depending on the pqcrypto_fm plugin. These are standalone definitions.
"""

from acapy_agent.wallet.key_type import KeyType


# ML-DSA-65 (Dilithium3) - NIST FIPS-204 Digital Signature Algorithm
ML_DSA_65 = KeyType(
    key_type="ml-dsa-65",
    multicodec_name="ml-dsa-65-pub",
    multicodec_prefix=b"\xd0\x65",
    jws_alg="PQC-DSA",
)

# ML-KEM-768 (Kyber768) - NIST FIPS-203 Key Encapsulation Mechanism
ML_KEM_768 = KeyType(
    key_type="ml-kem-768",
    multicodec_name="ml-kem-768-pub",
    multicodec_prefix=b"\xe0\x18",
    jws_alg=None,  # KEM algorithms don't have JWS algorithms
)

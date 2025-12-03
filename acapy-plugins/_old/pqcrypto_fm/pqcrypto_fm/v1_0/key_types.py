"""PQC Key Types for ACA-Py integration."""

from acapy_agent.wallet.key_type import KeyType


# Post-Quantum Signature Key Types
ML_DSA_44 = KeyType("ml-dsa-44", "ml-dsa-44-pub", b"\xd0\x44", "PQC-DSA")
ML_DSA_65 = KeyType("ml-dsa-65", "ml-dsa-65-pub", b"\xd0\x65", "PQC-DSA")
ML_DSA_87 = KeyType("ml-dsa-87", "ml-dsa-87-pub", b"\xd0\x87", "PQC-DSA")

DILITHIUM2 = KeyType("dilithium2", "dilithium2-pub", b"\xd1\x02", "PQC-DSA")
DILITHIUM3 = KeyType("dilithium3", "dilithium3-pub", b"\xd1\x03", "PQC-DSA")
DILITHIUM5 = KeyType("dilithium5", "dilithium5-pub", b"\xd1\x05", "PQC-DSA")

FALCON_512 = KeyType("falcon-512", "falcon-512-pub", b"\xd2\x12", "PQC-DSA")
FALCON_1024 = KeyType("falcon-1024", "falcon-1024-pub", b"\xd2\x24", "PQC-DSA")

SPHINCS_SHA2_128F_SIMPLE = KeyType("sphincs-sha2-128f-simple", "sphincs-sha2-128f-simple-pub", b"\xd3\x11", "PQC-DSA")
SPHINCS_SHA2_128S_SIMPLE = KeyType("sphincs-sha2-128s-simple", "sphincs-sha2-128s-simple-pub", b"\xd3\x12", "PQC-DSA")
SPHINCS_SHA2_192F_SIMPLE = KeyType("sphincs-sha2-192f-simple", "sphincs-sha2-192f-simple-pub", b"\xd3\x21", "PQC-DSA")
SPHINCS_SHA2_192S_SIMPLE = KeyType("sphincs-sha2-192s-simple", "sphincs-sha2-192s-simple-pub", b"\xd3\x22", "PQC-DSA")
SPHINCS_SHA2_256F_SIMPLE = KeyType("sphincs-sha2-256f-simple", "sphincs-sha2-256f-simple-pub", b"\xd3\x31", "PQC-DSA")
SPHINCS_SHA2_256S_SIMPLE = KeyType("sphincs-sha2-256s-simple", "sphincs-sha2-256s-simple-pub", b"\xd3\x32", "PQC-DSA")

# Post-Quantum Key Encapsulation Key Types (no JWS algorithm for KEM)
ML_KEM_512 = KeyType("ml-kem-512", "ml-kem-512-pub", b"\xe0\x12", None)
ML_KEM_768 = KeyType("ml-kem-768", "ml-kem-768-pub", b"\xe0\x18", None)
ML_KEM_1024 = KeyType("ml-kem-1024", "ml-kem-1024-pub", b"\xe0\x24", None)

KYBER512 = KeyType("kyber512", "kyber512-pub", b"\xe1\x12", None)
KYBER768 = KeyType("kyber768", "kyber768-pub", b"\xe1\x18", None)
KYBER1024 = KeyType("kyber1024", "kyber1024-pub", b"\xe1\x24", None)

FRODOKEM_640_AES = KeyType("frodokem-640-aes", "frodokem-640-aes-pub", b"\xe2\x64", None)
FRODOKEM_640_SHAKE = KeyType("frodokem-640-shake", "frodokem-640-shake-pub", b"\xe2\x65", None)
FRODOKEM_976_AES = KeyType("frodokem-976-aes", "frodokem-976-aes-pub", b"\xe2\x76", None)
FRODOKEM_976_SHAKE = KeyType("frodokem-976-shake", "frodokem-976-shake-pub", b"\xe2\x77", None)
FRODOKEM_1344_AES = KeyType("frodokem-1344-aes", "frodokem-1344-aes-pub", b"\xe2\x84", None)
FRODOKEM_1344_SHAKE = KeyType("frodokem-1344-shake", "frodokem-1344-shake-pub", b"\xe2\x85", None)

NTRU_HPS_2048_509 = KeyType("ntru-hps-2048-509", "ntru-hps-2048-509-pub", b"\xe3\x09", None)
NTRU_HPS_2048_677 = KeyType("ntru-hps-2048-677", "ntru-hps-2048-677-pub", b"\xe3\x77", None)
NTRU_HPS_4096_821 = KeyType("ntru-hps-4096-821", "ntru-hps-4096-821-pub", b"\xe3\x21", None)
NTRU_HRSS_701 = KeyType("ntru-hrss-701", "ntru-hrss-701-pub", b"\xe3\x01", None)

SABER_LIGHTSABER = KeyType("saber-lightsaber", "saber-lightsaber-pub", b"\xe4\x01", None)
SABER_SABER = KeyType("saber-saber", "saber-saber-pub", b"\xe4\x02", None)
SABER_FIRESABER = KeyType("saber-firesaber", "saber-firesaber-pub", b"\xe4\x03", None)

# Hybrid Key Types (PQC + Classical)
HYBRID_ML_DSA_65_ED25519 = KeyType("hybrid-ml-dsa-65-ed25519", "hybrid-ml-dsa-65-ed25519-pub", b"\xf0\x65", "PQC-Hybrid-DSA")
HYBRID_DILITHIUM3_ED25519 = KeyType("hybrid-dilithium3-ed25519", "hybrid-dilithium3-ed25519-pub", b"\xf1\x03", "PQC-Hybrid-DSA")
HYBRID_ML_KEM_768_X25519 = KeyType("hybrid-ml-kem-768-x25519", "hybrid-ml-kem-768-x25519-pub", b"\xf0\x18", None)
HYBRID_KYBER768_X25519 = KeyType("hybrid-kyber768-x25519", "hybrid-kyber768-x25519-pub", b"\xf1\x18", None)

# Collection of all PQC key types
PQC_SIGNATURE_KEY_TYPES = [
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
    DILITHIUM2, DILITHIUM3, DILITHIUM5,
    FALCON_512, FALCON_1024,
    SPHINCS_SHA2_128F_SIMPLE, SPHINCS_SHA2_128S_SIMPLE,
    SPHINCS_SHA2_192F_SIMPLE, SPHINCS_SHA2_192S_SIMPLE,
    SPHINCS_SHA2_256F_SIMPLE, SPHINCS_SHA2_256S_SIMPLE,
]

PQC_KEM_KEY_TYPES = [
    ML_KEM_512, ML_KEM_768, ML_KEM_1024,
    KYBER512, KYBER768, KYBER1024,
    FRODOKEM_640_AES, FRODOKEM_640_SHAKE,
    FRODOKEM_976_AES, FRODOKEM_976_SHAKE,
    FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE,
    NTRU_HPS_2048_509, NTRU_HPS_2048_677,
    NTRU_HPS_4096_821, NTRU_HRSS_701,
    SABER_LIGHTSABER, SABER_SABER, SABER_FIRESABER,
]

PQC_HYBRID_KEY_TYPES = [
    HYBRID_ML_DSA_65_ED25519, HYBRID_DILITHIUM3_ED25519,
    HYBRID_ML_KEM_768_X25519, HYBRID_KYBER768_X25519,
]

PQC_KEY_TYPES = PQC_SIGNATURE_KEY_TYPES + PQC_KEM_KEY_TYPES + PQC_HYBRID_KEY_TYPES

# Default key types for different use cases
DEFAULT_PQC_SIGNATURE_KEY_TYPE = ML_DSA_65
DEFAULT_PQC_KEM_KEY_TYPE = ML_KEM_768
DEFAULT_HYBRID_SIGNATURE_KEY_TYPE = HYBRID_ML_DSA_65_ED25519
DEFAULT_HYBRID_KEM_KEY_TYPE = HYBRID_ML_KEM_768_X25519


def get_signature_key_types():
    """Get all signature key types."""
    return PQC_SIGNATURE_KEY_TYPES + [DEFAULT_HYBRID_SIGNATURE_KEY_TYPE]


def get_kem_key_types():
    """Get all KEM key types."""
    return PQC_KEM_KEY_TYPES + [DEFAULT_HYBRID_KEM_KEY_TYPE]


def get_hybrid_key_types():
    """Get all hybrid key types."""
    return PQC_HYBRID_KEY_TYPES


def is_pqc_key_type(key_type: KeyType) -> bool:
    """Check if a key type is a PQC key type."""
    return key_type in PQC_KEY_TYPES


def is_signature_key_type(key_type: KeyType) -> bool:
    """Check if a key type is a signature key type."""
    return key_type in (PQC_SIGNATURE_KEY_TYPES + [DEFAULT_HYBRID_SIGNATURE_KEY_TYPE])


def is_kem_key_type(key_type: KeyType) -> bool:
    """Check if a key type is a KEM key type."""
    return key_type in (PQC_KEM_KEY_TYPES + [DEFAULT_HYBRID_KEM_KEY_TYPE])


def is_hybrid_key_type(key_type: KeyType) -> bool:
    """Check if a key type is a hybrid key type."""
    return key_type in PQC_HYBRID_KEY_TYPES
"""Utility functions for PQC DID operations."""

import hashlib
import base58
import re
from typing import Optional
import base64


def generate_did_identifier(public_key_bytes: bytes, network: str) -> str:
    """Generate DID identifier from public key.

    Args:
        public_key_bytes: Public key bytes
        network: Network identifier

    Returns:
        DID identifier
    """
    # Create hash of public key + network
    hash_input = public_key_bytes + network.encode()
    sha256_hash = hashlib.sha256(hash_input).digest()

    # Use first 16 bytes for identifier
    identifier_bytes = sha256_hash[:16]

    # Encode as base58
    identifier = base58.b58encode(identifier_bytes).decode()

    return identifier


def validate_did_format(did: str, expected_method: str) -> bool:
    """Validate DID format.

    Args:
        did: DID to validate
        expected_method: Expected DID method

    Returns:
        True if valid
    """
    # Basic DID format check
    did_pattern = r'^did:([a-z0-9-]+):([a-z0-9]+):([a-zA-Z0-9._-]+)$'
    match = re.match(did_pattern, did)

    if not match:
        return False

    method, network, identifier = match.groups()

    # Check method matches
    if method != expected_method.replace("did:", ""):
        return False

    # Validate identifier length and format
    if len(identifier) < 16 or len(identifier) > 64:
        return False

    return True


def extract_did_components(did: str) -> Optional[dict]:
    """Extract components from DID.

    Args:
        did: DID to parse

    Returns:
        Dictionary with method, network, identifier
    """
    did_pattern = r'^did:([a-z0-9-]+):([a-z0-9]+):([a-zA-Z0-9._-]+)$'
    match = re.match(did_pattern, did)

    if not match:
        return None

    method, network, identifier = match.groups()

    return {
        "method": f"did:{method}",
        "network": network,
        "identifier": identifier
    }


def create_verification_method_id(did: str, key_id: str) -> str:
    """Create verification method ID.

    Args:
        did: Base DID
        key_id: Key identifier

    Returns:
        Full verification method ID
    """
    if key_id.startswith("#"):
        return f"{did}{key_id}"
    else:
        return f"{did}#{key_id}"


def extract_fragment_from_vm_id(vm_id: str) -> str:
    """Extract fragment from verification method ID.

    Args:
        vm_id: Verification method ID

    Returns:
        Fragment part
    """
    if "#" in vm_id:
        return vm_id.split("#")[-1]
    return vm_id


def is_pqc_verification_method(vm: dict) -> bool:
    """Check if verification method uses PQC.

    Args:
        vm: Verification method dictionary

    Returns:
        True if PQC verification method
    """
    pqc_types = {
        "PQCVerificationKey2024",
        "MLDSAVerificationKey2024",
        "MLKEMVerificationKey2024",
        "PQCSignatureKey2024"
    }

    return vm.get("type") in pqc_types or "pqcAlgorithm" in vm


def encode_public_key_multibase(public_key_bytes: bytes, encoding: str = "base64") -> str:
    """Encode public key as multibase.

    Args:
        public_key_bytes: Public key bytes
        encoding: Encoding format

    Returns:
        Multibase encoded public key
    """
    if encoding == "base64":
        # Use base64 encoding with prefix
        return "z" + base64.b64encode(public_key_bytes).decode()
    elif encoding == "base58btc":
        # Use base58btc encoding with prefix
        return "z" + base58.b58encode(public_key_bytes).decode()
    else:
        # Default to base64
        return "z" + base64.b64encode(public_key_bytes).decode()


def decode_public_key_multibase(multibase_key: str) -> bytes:
    """Decode multibase public key.

    Args:
        multibase_key: Multibase encoded key

    Returns:
        Public key bytes
    """
    if multibase_key.startswith("z"):
        # Remove prefix and decode as base64
        return base64.b64decode(multibase_key[1:])
    else:
        # Assume base64 without prefix
        return base64.b64decode(multibase_key)


def normalize_did_url(did_url: str) -> dict:
    """Normalize DID URL into components.

    Args:
        did_url: DID URL to normalize

    Returns:
        Dictionary with did, fragment, query, params
    """
    # Split on fragment
    if "#" in did_url:
        did_part, fragment = did_url.split("#", 1)
    else:
        did_part, fragment = did_url, None

    # Split on query
    if "?" in did_part:
        did_part, query = did_part.split("?", 1)
    else:
        query = None

    # Parse query parameters
    params = {}
    if query:
        for param in query.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                params[key] = value

    return {
        "did": did_part,
        "fragment": fragment,
        "query": query,
        "params": params
    }


def build_did_url(did: str, fragment: str = None, params: dict = None) -> str:
    """Build DID URL from components.

    Args:
        did: Base DID
        fragment: Fragment identifier
        params: Query parameters

    Returns:
        Complete DID URL
    """
    url = did

    # Add query parameters
    if params:
        query_parts = [f"{k}={v}" for k, v in params.items()]
        url += "?" + "&".join(query_parts)

    # Add fragment
    if fragment:
        if not fragment.startswith("#"):
            fragment = f"#{fragment}"
        url += fragment

    return url


def create_pqc_context() -> list:
    """Create JSON-LD context for PQC DID documents.

    Returns:
        List of context URLs
    """
    return [
        "https://www.w3.org/ns/did/v1",
        "https://pqc-consortium.org/contexts/pqc-v1.jsonld",
        "https://hedera.com/contexts/hedera-v1.jsonld",
        {
            "PQCVerificationKey2024": "https://pqc-consortium.org/2024/PQCVerificationKey",
            "MLDSAVerificationKey2024": "https://nist.gov/pqc/ML-DSA",
            "MLKEMVerificationKey2024": "https://nist.gov/pqc/ML-KEM",
            "pqcAlgorithm": "https://pqc-consortium.org/pqcAlgorithm",
            "keyEncoding": "https://pqc-consortium.org/keyEncoding",
            "quantumSafe": "https://pqc-consortium.org/quantumSafe",
            "hederaNetwork": "https://hedera.com/hederaNetwork",
            "topicId": "https://hedera.com/topicId",
            "consensusTimestamp": "https://hedera.com/consensusTimestamp"
        }
    ]


def validate_pqc_algorithm(algorithm: str) -> bool:
    """Validate PQC algorithm name.

    Args:
        algorithm: Algorithm name to validate

    Returns:
        True if valid PQC algorithm
    """
    valid_algorithms = {
        # NIST ML-DSA (Dilithium)
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "Dilithium2", "Dilithium3", "Dilithium5",

        # NIST ML-KEM (Kyber)
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "Kyber512", "Kyber768", "Kyber1024",

        # Other PQC algorithms
        "FALCON-512", "FALCON-1024",
        "SPHINCS+-SHA2-128s", "SPHINCS+-SHA2-128f",
        "SPHINCS+-SHA2-192s", "SPHINCS+-SHA2-192f",
        "SPHINCS+-SHA2-256s", "SPHINCS+-SHA2-256f",

        # Hybrid algorithms (for future use)
        "ML-DSA-65+Ed25519", "ML-KEM-768+X25519"
    }

    return algorithm in valid_algorithms


def get_algorithm_family(algorithm: str) -> str:
    """Get algorithm family from algorithm name.

    Args:
        algorithm: Algorithm name

    Returns:
        Algorithm family (signature, kem, etc.)
    """
    if any(alg in algorithm for alg in ["ML-DSA", "Dilithium", "FALCON", "SPHINCS"]):
        return "signature"
    elif any(alg in algorithm for alg in ["ML-KEM", "Kyber"]):
        return "kem"
    else:
        return "unknown"


def generate_pqc_key_id(algorithm: str, public_key_bytes: bytes) -> str:
    """Generate key ID for PQC key.

    Args:
        algorithm: PQC algorithm
        public_key_bytes: Public key bytes

    Returns:
        Key identifier
    """
    # Create hash of algorithm + public key
    hash_input = algorithm.encode() + public_key_bytes
    sha256_hash = hashlib.sha256(hash_input).digest()

    # Use first 8 bytes for key ID
    key_id_bytes = sha256_hash[:8]

    # Encode as base58
    key_id = base58.b58encode(key_id_bytes).decode()

    return f"pqc-{algorithm.lower().replace('-', '')}-{key_id}"
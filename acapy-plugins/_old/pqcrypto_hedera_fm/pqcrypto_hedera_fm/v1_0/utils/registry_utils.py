"""Utility functions for PQC registry operations."""

import hashlib
import base58
from typing import Dict, Any
import re


def generate_schema_id(issuer_did: str, name: str, version: str) -> str:
    """Generate schema ID from components.

    Args:
        issuer_did: Issuer DID
        name: Schema name
        version: Schema version

    Returns:
        Schema identifier
    """
    # Format: did:method:network:identifier/schema/name/version
    # For PQC schemas: did:hedera-pqc:network:identifier/schema/name/version

    # Extract network and identifier from DID
    did_parts = issuer_did.split(":")
    if len(did_parts) >= 4:
        method = ":".join(did_parts[:3])  # did:hedera-pqc:network
        identifier = did_parts[3]
    else:
        # Fallback
        method = "did:hedera-pqc:testnet"
        identifier = "unknown"

    # Clean name and version for ID
    clean_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    clean_version = re.sub(r'[^a-zA-Z0-9._-]', '_', version)

    schema_id = f"{method}:{identifier}/schema/{clean_name}/{clean_version}"

    return schema_id


def generate_creddef_id(issuer_did: str, schema_id: str, tag: str) -> str:
    """Generate credential definition ID from components.

    Args:
        issuer_did: Issuer DID
        schema_id: Schema ID
        tag: Credential definition tag

    Returns:
        Credential definition identifier
    """
    # Format: did:method:network:identifier/creddef/schema_hash/tag

    # Extract components from issuer DID
    did_parts = issuer_did.split(":")
    if len(did_parts) >= 4:
        method = ":".join(did_parts[:3])  # did:hedera-pqc:network
        identifier = did_parts[3]
    else:
        # Fallback
        method = "did:hedera-pqc:testnet"
        identifier = "unknown"

    # Create hash of schema ID for brevity
    schema_hash = hashlib.sha256(schema_id.encode()).hexdigest()[:16]

    # Clean tag
    clean_tag = re.sub(r'[^a-zA-Z0-9_-]', '_', tag)

    creddef_id = f"{method}:{identifier}/creddef/{schema_hash}/{clean_tag}"

    return creddef_id


def generate_revocation_registry_id(creddef_id: str, tag: str) -> str:
    """Generate revocation registry ID from components.

    Args:
        creddef_id: Credential definition ID
        tag: Revocation registry tag

    Returns:
        Revocation registry identifier
    """
    # Extract base from creddef ID
    if "/creddef/" in creddef_id:
        base_did = creddef_id.split("/creddef/")[0]
        creddef_hash = hashlib.sha256(creddef_id.encode()).hexdigest()[:16]
    else:
        base_did = "did:hedera-pqc:testnet:unknown"
        creddef_hash = "unknown"

    # Clean tag
    clean_tag = re.sub(r'[^a-zA-Z0-9_-]', '_', tag)

    revreg_id = f"{base_did}/revreg/{creddef_hash}/{clean_tag}"

    return revreg_id


def parse_schema_id(schema_id: str) -> Dict[str, str]:
    """Parse schema ID into components.

    Args:
        schema_id: Schema ID to parse

    Returns:
        Dictionary with parsed components
    """
    # Expected format: did:method:network:identifier/schema/name/version
    pattern = r'^(did:[^:]+:[^:]+:[^/]+)/schema/([^/]+)/([^/]+)$'
    match = re.match(pattern, schema_id)

    if match:
        issuer_did, name, version = match.groups()
        return {
            "issuerDid": issuer_did,
            "name": name,
            "version": version
        }

    return {}


def parse_creddef_id(creddef_id: str) -> Dict[str, str]:
    """Parse credential definition ID into components.

    Args:
        creddef_id: Credential definition ID to parse

    Returns:
        Dictionary with parsed components
    """
    # Expected format: did:method:network:identifier/creddef/schema_hash/tag
    pattern = r'^(did:[^:]+:[^:]+:[^/]+)/creddef/([^/]+)/([^/]+)$'
    match = re.match(pattern, creddef_id)

    if match:
        issuer_did, schema_hash, tag = match.groups()
        return {
            "issuerDid": issuer_did,
            "schemaHash": schema_hash,
            "tag": tag
        }

    return {}


def validate_schema_id(schema_id: str) -> bool:
    """Validate schema ID format.

    Args:
        schema_id: Schema ID to validate

    Returns:
        True if valid
    """
    pattern = r'^did:[^:]+:[^:]+:[^/]+/schema/[^/]+/[^/]+$'
    return bool(re.match(pattern, schema_id))


def validate_creddef_id(creddef_id: str) -> bool:
    """Validate credential definition ID format.

    Args:
        creddef_id: Credential definition ID to validate

    Returns:
        True if valid
    """
    pattern = r'^did:[^:]+:[^:]+:[^/]+/creddef/[^/]+/[^/]+$'
    return bool(re.match(pattern, creddef_id))


def validate_revreg_id(revreg_id: str) -> bool:
    """Validate revocation registry ID format.

    Args:
        revreg_id: Revocation registry ID to validate

    Returns:
        True if valid
    """
    pattern = r'^did:[^:]+:[^:]+:[^/]+/revreg/[^/]+/[^/]+$'
    return bool(re.match(pattern, revreg_id))


def extract_did_from_registry_id(registry_id: str) -> str:
    """Extract DID from registry ID.

    Args:
        registry_id: Registry ID (schema, creddef, or revreg)

    Returns:
        Extracted DID
    """
    # Find the DID portion before the first slash
    if "/" in registry_id:
        return registry_id.split("/")[0]

    return registry_id


def create_registry_metadata(
    registry_type: str,
    algorithm_suite: Dict[str, str],
    network: str
) -> Dict[str, Any]:
    """Create metadata for registry entries.

    Args:
        registry_type: Type of registry entry (schema, creddef, revreg)
        algorithm_suite: PQC algorithm suite
        network: Network identifier

    Returns:
        Metadata dictionary
    """
    return {
        "registryType": registry_type,
        "pqcAlgorithmSuite": algorithm_suite,
        "network": network,
        "quantumSafe": True,
        "version": "1.0",
        "standard": "PQC-Registry-v1"
    }


def generate_attribute_hash(attribute_name: str, algorithm: str) -> str:
    """Generate hash for attribute in PQC context.

    Args:
        attribute_name: Name of the attribute
        algorithm: PQC algorithm used

    Returns:
        Attribute hash
    """
    hash_input = f"{attribute_name}:{algorithm}".encode()
    hash_digest = hashlib.sha256(hash_input).digest()

    # Use base58 encoding for compatibility
    return base58.b58encode(hash_digest[:16]).decode()


def create_pqc_proof_type(algorithm: str) -> str:
    """Create proof type identifier for PQC algorithm.

    Args:
        algorithm: PQC algorithm name

    Returns:
        Proof type identifier
    """
    # Normalize algorithm name
    normalized = algorithm.upper().replace("-", "_")

    # Map to proof types
    proof_type_map = {
        "ML_DSA_44": "MLDSASignature2024",
        "ML_DSA_65": "MLDSASignature2024",
        "ML_DSA_87": "MLDSASignature2024",
        "DILITHIUM2": "DilithiumSignature2024",
        "DILITHIUM3": "DilithiumSignature2024",
        "DILITHIUM5": "DilithiumSignature2024",
        "FALCON_512": "FalconSignature2024",
        "FALCON_1024": "FalconSignature2024"
    }

    return proof_type_map.get(normalized, "PQCSignature2024")


def validate_attribute_list(attributes: list) -> Dict[str, Any]:
    """Validate attribute list for schema.

    Args:
        attributes: List of attribute names

    Returns:
        Validation result with errors and warnings
    """
    errors = []
    warnings = []

    if not attributes:
        errors.append("Attribute list cannot be empty")
        return {"valid": False, "errors": errors, "warnings": warnings}

    # Check for duplicates
    seen = set()
    for attr in attributes:
        if not isinstance(attr, str):
            errors.append(f"Attribute must be string: {attr}")
            continue

        if not attr.strip():
            errors.append("Attribute cannot be empty or whitespace")
            continue

        if attr in seen:
            errors.append(f"Duplicate attribute: {attr}")
        else:
            seen.add(attr)

        # Check for reserved names
        reserved_names = {
            "master_secret", "master-secret", "masterSecret",
            "link_secret", "link-secret", "linkSecret"
        }

        if attr.lower() in reserved_names:
            warnings.append(f"Attribute name '{attr}' conflicts with reserved names")

        # Check attribute name format
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_.-]*$', attr):
            warnings.append(f"Attribute '{attr}' should start with letter and contain only alphanumeric, underscore, dot, hyphen")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }


def normalize_registry_id(registry_id: str) -> str:
    """Normalize registry ID format.

    Args:
        registry_id: Registry ID to normalize

    Returns:
        Normalized registry ID
    """
    # Remove extra whitespace
    normalized = registry_id.strip()

    # Ensure lowercase for method and network parts
    parts = normalized.split("/")
    if parts and ":" in parts[0]:
        did_parts = parts[0].split(":")
        if len(did_parts) >= 3:
            # Lowercase method and network, preserve identifier
            did_parts[1] = did_parts[1].lower()  # method
            did_parts[2] = did_parts[2].lower()  # network
            parts[0] = ":".join(did_parts)

    return "/".join(parts)


def get_registry_type_from_id(registry_id: str) -> str:
    """Determine registry type from ID.

    Args:
        registry_id: Registry ID

    Returns:
        Registry type (schema, creddef, revreg, or unknown)
    """
    if "/schema/" in registry_id:
        return "schema"
    elif "/creddef/" in registry_id:
        return "creddef"
    elif "/revreg/" in registry_id:
        return "revreg"
    else:
        return "unknown"
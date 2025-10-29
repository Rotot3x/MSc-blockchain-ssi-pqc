"""Patch for ConnectionTarget schema validation to accept PQC keys.

This patch extends the ConnectionTargetSchema to accept both classical ED25519 keys
and Post-Quantum keys (ML-DSA-65, ML-KEM-768).

CRITICAL FIX for credential issuance:
- Original schema validates recipient_keys, routing_keys, and sender_key as ED25519
- Validation pattern: ^[1-9A-HJ-NP-Za-km-z]{43,44}$ (43-44 base58 chars)
- PQC keys have different byte lengths and base58 representations:
  - ML-DSA-65: 1952 bytes → ~2650 base58 chars
  - ML-KEM-768: 1184 bytes → ~1600 base58 chars
- Original validation fails with: "Value X is not a raw Ed25519VerificationKey2018 key"

This patch:
1. Creates a new validator that accepts both ED25519 and PQC key formats
2. Patches the ConnectionTargetSchema fields to use the new validator
3. Preserves backward compatibility with ED25519 workflows

Applied during plugin initialization in __init__.py setup().
"""

import logging
import re
from marshmallow.validate import Regexp
from base58 import alphabet

LOGGER = logging.getLogger(__name__)

# Base58 character set (from acapy_agent/messaging/valid.py:16)
B58 = alphabet if isinstance(alphabet, str) else alphabet.decode("ascii")


class RawPublicKeyAnyAlgorithm(Regexp):
    """Validate value against raw public key (any supported algorithm).

    This validator accepts:
    1. ED25519 keys (43-44 base58 characters)
    2. ML-DSA-65 keys (~2650 base58 characters)
    3. ML-KEM-768 keys (~1600 base58 characters)

    Pattern: Any non-empty base58 string (minimum 32 chars to prevent trivial inputs)
    """

    EXAMPLE = "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"  # ED25519 example
    # Accept any base58 string with reasonable length (32+ chars to prevent abuse)
    PATTERN = rf"^[{B58}]{{32,}}$"

    def __init__(self):
        """Initialize the instance."""
        super().__init__(
            RawPublicKeyAnyAlgorithm.PATTERN,
            error="Value {input} is not a valid raw public key (must be base58, 32+ chars)",
        )


# Create validator instance
RAW_PUBLIC_KEY_ANY_ALGORITHM_VALIDATE = RawPublicKeyAnyAlgorithm()


def patch_connection_target_schema():
    """Patch ConnectionTargetSchema to accept PQC keys.

    This function:
    1. Imports the ConnectionTargetSchema class
    2. Replaces the validators for recipient_keys, routing_keys, and sender_key
    3. Uses the new RawPublicKeyAnyAlgorithm validator that accepts both ED25519 and PQC

    IMPORTANT: This must be called AFTER acapy_agent is imported but BEFORE
    any ConnectionTarget objects are deserialized.
    """
    from acapy_agent.connections.models.connection_target import ConnectionTargetSchema
    from marshmallow import fields

    LOGGER.info("🔧 Patching ConnectionTargetSchema to accept PQC keys...")

    # Store original field definitions for logging
    original_recipient_keys = ConnectionTargetSchema._declared_fields.get('recipient_keys')
    original_routing_keys = ConnectionTargetSchema._declared_fields.get('routing_keys')
    original_sender_key = ConnectionTargetSchema._declared_fields.get('sender_key')

    LOGGER.debug(f"  Original recipient_keys validator: {original_recipient_keys}")
    LOGGER.debug(f"  Original routing_keys validator: {original_routing_keys}")
    LOGGER.debug(f"  Original sender_key validator: {original_sender_key}")

    # Patch recipient_keys field
    ConnectionTargetSchema._declared_fields['recipient_keys'] = fields.List(
        fields.Str(
            validate=RAW_PUBLIC_KEY_ANY_ALGORITHM_VALIDATE,
            metadata={
                "description": "Recipient public key (ED25519, ML-DSA-65, or ML-KEM-768)",
                "example": RawPublicKeyAnyAlgorithm.EXAMPLE,
            },
        ),
        required=False,
        metadata={"description": "List of recipient keys"},
    )

    # Patch routing_keys field
    ConnectionTargetSchema._declared_fields['routing_keys'] = fields.List(
        fields.Str(
            validate=RAW_PUBLIC_KEY_ANY_ALGORITHM_VALIDATE,
            metadata={
                "description": "Routing key (ED25519, ML-DSA-65, or ML-KEM-768)",
                "example": RawPublicKeyAnyAlgorithm.EXAMPLE,
            },
        ),
        data_key="routingKeys",
        required=False,
        metadata={"description": "List of routing keys"},
    )

    # Patch sender_key field
    ConnectionTargetSchema._declared_fields['sender_key'] = fields.Str(
        required=False,
        validate=RAW_PUBLIC_KEY_ANY_ALGORITHM_VALIDATE,
        metadata={
            "description": "Sender public key (ED25519, ML-DSA-65, or ML-KEM-768)",
            "example": RawPublicKeyAnyAlgorithm.EXAMPLE,
        },
    )

    LOGGER.info("  ✅ recipient_keys field patched to accept PQC keys")
    LOGGER.info("  ✅ routing_keys field patched to accept PQC keys")
    LOGGER.info("  ✅ sender_key field patched to accept PQC keys")
    LOGGER.info("     New pattern: base58 strings with 32+ characters")
    LOGGER.info("     Accepts: ED25519 (43-44 chars), ML-DSA-65 (~2650 chars), ML-KEM-768 (~1600 chars)")

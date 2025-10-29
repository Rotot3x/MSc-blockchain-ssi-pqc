"""Patch JWSHeaderKid validator to accept did:peer:4 format.

This patch extends the JWSHeaderKid validator in ACA-Py to accept did:peer:4
DID URLs with fragments (e.g., did:peer:4zQm...#key-1), which are used in
JWS header 'kid' fields during DID Exchange protocol.

The original validator only accepts:
- did:key:z[base58]+
- did:sov:[base58]{21-22}#...

The patched validator also accepts:
- did:peer:2...#key-X (existing peer method)
- did:peer:3...#key-X (existing peer method)
- did:peer:4...#key-X (new peer method with PQC support)

This patch is necessary because did:peer:4 DIDs can be very long when they
contain Post-Quantum Cryptography keys (ML-DSA-65 public keys are 1952 bytes,
resulting in did:peer:4 DIDs that are thousands of characters long when
multibase-encoded).
"""

import logging
from acapy_agent.messaging.valid import JWSHeaderKid, B58
import acapy_agent.messaging.valid as valid_module

LOGGER = logging.getLogger(__name__)


def patch_jws_header_kid_for_peer4():
    """Patch JWSHeaderKid validator to accept did:peer:4 DIDs.

    This function monkey-patches the JWSHeaderKid validator by:
    1. Updating the JWSHeaderKid.PATTERN class variable
    2. Creating a NEW validator instance with the updated pattern
    3. Replacing the global JWS_HEADER_KID_VALIDATE instance
    4. Patching all modules that cached the old validator instance

    The regex pattern is compiled in __init__, so we MUST create a new instance
    after changing the pattern, otherwise the old compiled regex will be used.

    CRITICAL: Python's import mechanism caches references to objects. Modules
    that imported JWS_HEADER_KID_VALIDATE before this patch still have references
    to the OLD validator instance. We must patch those cached references too!

    The new pattern maintains backward compatibility with existing did:key
    and did:sov formats while adding support for did:peer methods.

    Pattern breakdown:
    - ^did:(?:                         # Start with 'did:' prefix
    -   key:z[{B58}]+                  # did:key format (W3C)
    -   |sov:[{B58}]{{21,22}}          # did:sov format (Indy)
    -     (;.*)?(\?.*)?                # Optional parameters for did:sov
    -   |peer:[2-4].+                  # did:peer:2/3/4 format (NEW!)
    - )#.+$                            # Fragment identifier (e.g., #key-1)

    Examples of accepted DIDs:
    - did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
    - did:sov:Q4zqM7aXqm7gDQkUVLng9h#keys-1
    - did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6Mk...#key-1
    - did:peer:4zQmZDCy...z25gYmQo...#key-1 (PQC long form, thousands of chars)
    - did:peer:4zEYJrM...#key-1 (short form)
    """
    # Store original pattern for debugging
    original_pattern = JWSHeaderKid.PATTERN

    # Step 1: Update the class variable pattern
    JWSHeaderKid.PATTERN = rf"^did:(?:key:z[{B58}]+|sov:[{B58}]{{21,22}}(;.*)?(\?.*)?|peer:[2-4].+)#.+$"

    # Step 2: Update the example to show did:peer:4 format
    JWSHeaderKid.EXAMPLE = "did:peer:4zQmZDCy8xgzL1ZskYJ3Wk92mBRT1yzmJZCJkaARmZHLCuK#key-1"

    # Step 3: Create NEW validator instance with updated pattern
    # This is CRITICAL! The regex is compiled in __init__(), so we need a fresh instance
    new_validator = JWSHeaderKid()

    # Step 4: Replace the global instance in valid module
    valid_module.JWS_HEADER_KID_VALIDATE = new_validator
    valid_module.JWS_HEADER_KID_EXAMPLE = JWSHeaderKid.EXAMPLE

    # Step 5: Patch cached references in modules that already imported the validator
    # CRITICAL: attach_decorator imports JWS_HEADER_KID_VALIDATE at module load time
    # If it was already imported (e.g., by askar_pqc_patch), it has a cached reference
    # to the OLD validator instance. We MUST replace that cached reference!
    import sys
    patched_modules = []

    if 'acapy_agent.messaging.decorators.attach_decorator' in sys.modules:
        attach_decorator_module = sys.modules['acapy_agent.messaging.decorators.attach_decorator']
        attach_decorator_module.JWS_HEADER_KID_VALIDATE = new_validator
        patched_modules.append("attach_decorator (module-level)")

        # CRITICAL: Marshmallow schema classes are defined at module load time with
        # the validator baked into the field definition. We must patch the schema
        # class field directly!
        # Line 72 of attach_decorator.py:
        #   kid = fields.Str(validate=JWS_HEADER_KID_VALIDATE, ...)
        # The validator reference is stored in the schema field's metadata.
        schema_class = attach_decorator_module.AttachDecoratorDataJWSHeaderSchema
        if hasattr(schema_class, '_declared_fields') and 'kid' in schema_class._declared_fields:
            # Patch the validator in the declared field
            schema_class._declared_fields['kid'].validators = [new_validator]
            patched_modules.append("AttachDecoratorDataJWSHeaderSchema.kid field")

        LOGGER.info(f"   ✅ Patched validator in: {', '.join(patched_modules)}")

    LOGGER.info("✅ JWSHeaderKid validator patched for did:peer:4 support")
    LOGGER.debug(f"   Original pattern: {original_pattern}")
    LOGGER.debug(f"   New pattern: {JWSHeaderKid.PATTERN}")
    LOGGER.debug(f"   Validator instance recreated: {new_validator}")
    LOGGER.debug(f"   Patched {len(patched_modules)} locations")

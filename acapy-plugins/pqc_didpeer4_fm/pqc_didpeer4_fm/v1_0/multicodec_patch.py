"""Patch ACA-Py's SupportedCodecs to recognize PQC multicodecs.

This module monkey-patches acapy_agent.utils.multiformats.multicodec.SupportedCodecs
to support ML-DSA-65 and ML-KEM-768 multicodec prefixes used in PQC multikeys.

Without this patch, ACA-Py's multicodec.unwrap() throws:
    ValueError: Unsupported multicodec
when encountering PQC keys in did:peer:4 documents.
"""

import logging
from typing import Optional

LOGGER = logging.getLogger(__name__)


def patch_supported_codecs():
    """Monkey-patch SupportedCodecs to support PQC multicodecs.

    This patches two methods:
    1. SupportedCodecs.for_data() - Used when unwrapping multicodec-prefixed keys
    2. SupportedCodecs.by_name() - Used when looking up codecs by name

    Both methods fall back to PQC_MULTICODECS registry if classical codecs
    don't match.
    """
    try:
        from acapy_agent.utils.multiformats.multicodec import (
            SupportedCodecs,
            Multicodec,
        )
        from .pqc_multicodec import PQC_MULTICODECS

        # Save original methods
        original_for_data = SupportedCodecs.for_data
        original_by_name = SupportedCodecs.by_name

        @classmethod
        def for_data_pqc(cls, data: bytes) -> Multicodec:
            """Enhanced for_data() that supports PQC multicodecs.

            Args:
                data: Multicodec-prefixed key bytes

            Returns:
                Multicodec object

            Raises:
                ValueError: If multicodec prefix is unknown
            """
            # Try classical codecs first (ED25519, X25519, etc.)
            try:
                return original_for_data(data)
            except ValueError:
                # Classical codec not found, try PQC registry
                for codec_name, prefix in PQC_MULTICODECS.items():
                    if data.startswith(prefix):
                        LOGGER.debug(f"Matched PQC multicodec: {codec_name}")
                        return Multicodec(codec_name, prefix)

                # Neither classical nor PQC codec matched
                prefix_hex = data[:2].hex() if len(data) >= 2 else "empty"
                raise ValueError(
                    f"Unsupported multicodec (prefix: 0x{prefix_hex}). "
                    f"Supported PQC: {list(PQC_MULTICODECS.keys())}"
                )

        @classmethod
        def by_name_pqc(cls, name: str) -> Multicodec:
            """Enhanced by_name() that supports PQC multicodecs.

            Args:
                name: Multicodec name (e.g., "ml-dsa-65-pub")

            Returns:
                Multicodec object

            Raises:
                ValueError: If multicodec name is unknown
            """
            # Try classical codecs first
            try:
                return original_by_name(name)
            except ValueError:
                # Classical codec not found, try PQC registry
                if name in PQC_MULTICODECS:
                    LOGGER.debug(f"Matched PQC multicodec by name: {name}")
                    return Multicodec(name, PQC_MULTICODECS[name])

                # Neither classical nor PQC codec matched
                raise ValueError(
                    f"Unsupported multicodec: {name}. "
                    f"Supported PQC: {list(PQC_MULTICODECS.keys())}"
                )

        # Apply monkey patches
        SupportedCodecs.for_data = for_data_pqc
        SupportedCodecs.by_name = by_name_pqc

        LOGGER.info("✅ Patched SupportedCodecs.for_data() for PQC support")
        LOGGER.info("✅ Patched SupportedCodecs.by_name() for PQC support")

    except ImportError as e:
        LOGGER.error(f"Failed to import multicodec module: {e}")
        raise
    except Exception as e:
        LOGGER.error(f"Unexpected error while patching SupportedCodecs: {e}")
        raise


def unpatch_supported_codecs():
    """Remove monkey patches and restore original SupportedCodecs methods.

    This function is provided for testing purposes. In normal operation,
    the patches should remain active.
    """
    # Note: Restoration would require storing original methods globally
    # For now, this is a placeholder for API consistency
    LOGGER.warning("unpatch_supported_codecs() not implemented - patches are permanent")

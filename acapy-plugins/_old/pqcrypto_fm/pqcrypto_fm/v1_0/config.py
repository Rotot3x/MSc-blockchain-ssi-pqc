"""Configuration for PQCrypto_FM Plugin."""

import logging
from typing import Dict, Any, Optional

LOGGER = logging.getLogger(__name__)


class PQCConfig:
    """Configuration class for PQC Plugin."""

    # Default PQC algorithms
    DEFAULT_SIGNATURE_ALGORITHM = "ML-DSA-65"  # NIST standard
    DEFAULT_KEM_ALGORITHM = "ML-KEM-768"      # NIST standard

    # Fallback algorithms if ML-* not available
    FALLBACK_SIGNATURE_ALGORITHM = "Dilithium3"
    FALLBACK_KEM_ALGORITHM = "Kyber768"

    def __init__(self, settings: Dict[str, Any]):
        """Initialize PQC configuration.

        Args:
            settings: ACA-Py settings dictionary
        """
        self.settings = settings

        # Core PQC settings
        self.enable_pqc = self._get_bool("pqc.enable", True)
        self.enable_hybrid_mode = self._get_bool("pqc.hybrid_mode", True)
        self.set_as_default = self._get_bool("pqc.set_as_default", True)

        # Algorithm preferences
        self.signature_algorithm = self._get_str(
            "pqc.signature_algorithm",
            self.DEFAULT_SIGNATURE_ALGORITHM
        )
        self.kem_algorithm = self._get_str(
            "pqc.kem_algorithm",
            self.DEFAULT_KEM_ALGORITHM
        )

        # Fallback algorithms
        self.fallback_signature_algorithm = self._get_str(
            "pqc.fallback_signature_algorithm",
            self.FALLBACK_SIGNATURE_ALGORITHM
        )
        self.fallback_kem_algorithm = self._get_str(
            "pqc.fallback_kem_algorithm",
            self.FALLBACK_KEM_ALGORITHM
        )

        # Performance and security settings
        self.enable_key_caching = self._get_bool("pqc.enable_key_caching", True)
        self.max_cached_keys = self._get_int("pqc.max_cached_keys", 100)
        self.key_expiry_seconds = self._get_int("pqc.key_expiry_seconds", 3600)

        # DID method settings
        self.default_did_method = self._get_str("pqc.default_did_method", "did:pqc")
        self.enable_did_pqc = self._get_bool("pqc.enable_did_pqc", True)
        self.enable_did_hybrid = self._get_bool("pqc.enable_did_hybrid", True)

        # Credential and proof settings
        self.enable_pqc_credentials = self._get_bool("pqc.enable_pqc_credentials", True)
        self.enable_pqc_proofs = self._get_bool("pqc.enable_pqc_proofs", True)

        # Logging and debugging
        self.debug_mode = self._get_bool("pqc.debug_mode", False)
        self.log_crypto_operations = self._get_bool("pqc.log_crypto_operations", False)

        LOGGER.info(f"PQC Config initialized: {self.get_summary()}")

    def _get_str(self, key: str, default: str) -> str:
        """Get string setting."""
        return self.settings.get(key, default)

    def _get_bool(self, key: str, default: bool) -> bool:
        """Get boolean setting."""
        value = self.settings.get(key, default)
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on")
        return bool(value)

    def _get_int(self, key: str, default: int) -> int:
        """Get integer setting."""
        try:
            return int(self.settings.get(key, default))
        except (ValueError, TypeError):
            return default

    def get_summary(self) -> str:
        """Get configuration summary."""
        return (
            f"PQC={self.enable_pqc}, "
            f"Hybrid={self.enable_hybrid_mode}, "
            f"Default={self.set_as_default}, "
            f"Sig={self.signature_algorithm}, "
            f"KEM={self.kem_algorithm}"
        )

    def is_algorithm_enabled(self, algorithm: str) -> bool:
        """Check if a specific algorithm is enabled."""
        return algorithm in [
            self.signature_algorithm,
            self.kem_algorithm,
            self.fallback_signature_algorithm,
            self.fallback_kem_algorithm
        ]

    def get_preferred_signature_algorithm(self) -> str:
        """Get the preferred signature algorithm."""
        return self.signature_algorithm

    def get_preferred_kem_algorithm(self) -> str:
        """Get the preferred KEM algorithm."""
        return self.kem_algorithm
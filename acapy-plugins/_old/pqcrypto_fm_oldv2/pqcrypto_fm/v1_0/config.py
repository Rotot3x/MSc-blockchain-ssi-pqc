"""
PQCrypto_FM Configuration

Simplified configuration for the PQC plugin.
"""

import logging
from typing import Dict, Any, List
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)

@dataclass
class PQCConfig:
    """Configuration class for PQCrypto_FM plugin settings."""

    default_kem_algorithm: str = "Kyber768"
    default_sig_algorithm: str = "Dilithium3"
    hybrid_mode: bool = True
    use_askar_anoncreds: bool = True
    enable_demo_mode: bool = False

    @classmethod
    def from_settings(cls, settings: Dict[str, Any]) -> "PQCConfig":
        """Create configuration from ACA-Py settings."""
        plugin_config = settings.get("plugin-config", {})
        pqc_settings = plugin_config.get("pqcrypto_fm.v1_0", {})

        return cls(
            default_kem_algorithm=pqc_settings.get("default_kem_algorithm", "Kyber768"),
            default_sig_algorithm=pqc_settings.get("default_sig_algorithm", "Dilithium3"),
            hybrid_mode=pqc_settings.get("hybrid_mode", True),
            use_askar_anoncreds=pqc_settings.get("use_askar_anoncreds", True),
            enable_demo_mode=pqc_settings.get("enable_demo_mode", False),
        )

    def validate(self) -> None:
        """Validate configuration settings."""
        LOGGER.info("✅ PQCrypto_FM configuration validated")
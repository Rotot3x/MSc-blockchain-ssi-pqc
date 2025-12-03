"""PQCrypto_FM v1.0 Configuration

Configuration management for Post-Quantum Cryptography plugin.
Updated for official ACA-Py plugin structure.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

LOGGER = logging.getLogger(__name__)


@dataclass
class PQCConfig:
    """Configuration class for PQCrypto_FM plugin settings."""

    # Default NIST-standardized algorithms
    default_kem_algorithm: str = "Kyber768"
    default_sig_algorithm: str = "Dilithium3"
    default_hash_sig_algorithm: str = "SPHINCS+-SHAKE-128s-simple"

    # Operating modes
    hybrid_mode: bool = True
    fallback_to_classical: bool = False
    quantum_safe_only: bool = False

    # Performance settings
    hardware_acceleration: bool = True
    key_cache_size: int = 2000
    batch_operations: bool = True

    # Security settings for production
    require_pqc_for_new_connections: bool = True
    min_security_level: int = 3  # NIST security levels 1-5 (3 = recommended)
    enable_pqc_for_credentials: bool = True
    enable_pqc_for_proofs: bool = True

    # Wallet integration
    use_askar_anoncreds: bool = True
    pqc_key_derivation: bool = True

    # Demo integration
    enable_demo_mode: bool = False
    demo_algorithms: Dict[str, str] = None

    # Algorithm configurations
    enabled_kem_algorithms: List[str] = None
    enabled_sig_algorithms: List[str] = None
    enabled_hash_sig_algorithms: List[str] = None

    def __post_init__(self):
        """Initialize default algorithm lists and demo config."""
        if self.enabled_kem_algorithms is None:
            self.enabled_kem_algorithms = [
                "Kyber512",  # NIST Level 1 - Fast
                "Kyber768",  # NIST Level 3 - Recommended
                "Kyber1024",  # NIST Level 5 - Maximum Security
            ]

        if self.enabled_sig_algorithms is None:
            self.enabled_sig_algorithms = [
                "Dilithium2",  # NIST Level 1 - Fast
                "Dilithium3",  # NIST Level 3 - Recommended
                "Dilithium5",  # NIST Level 5 - Maximum Security
            ]

        if self.enabled_hash_sig_algorithms is None:
            self.enabled_hash_sig_algorithms = [
                "SPHINCS+-SHAKE-128s-simple",  # Level 1
                "SPHINCS+-SHA2-128s-simple",  # Level 1
                "SPHINCS+-SHAKE-192s-simple",  # Level 3
                "SPHINCS+-SHA2-192s-simple",  # Level 3
            ]

        # Demo-specific algorithm configuration
        if self.demo_algorithms is None:
            self.demo_algorithms = {
                "faber": "Dilithium3",  # University issuer
                "alice": "Kyber768",  # Student holder
                "acme": "Dilithium3",  # Corporate verifier
                "performance": "Kyber512",  # Performance testing
            }

    @classmethod
    def from_settings(cls, settings: Dict[str, Any]) -> "PQCConfig":
        """Create configuration from ACA-Py settings.

        Args:
            settings: ACA-Py settings dictionary

        Returns:
            PQCConfig instance configured for production use
        """
        # Extract plugin-specific settings
        plugin_config = settings.get("plugin-config", {})
        pqc_settings = plugin_config.get("pqcrypto_fm.v1_0", {})

        # Check if demo mode is enabled
        demo_mode = settings.get("demo") or pqc_settings.get("enable_demo_mode", False)

        return cls(
            # Core algorithms
            default_kem_algorithm=pqc_settings.get("default_kem_algorithm", "Kyber768"),
            default_sig_algorithm=pqc_settings.get("default_sig_algorithm", "Dilithium3"),
            default_hash_sig_algorithm=pqc_settings.get(
                "default_hash_sig_algorithm", "SPHINCS+-SHAKE-128s-simple"
            ),
            # Operating modes
            hybrid_mode=pqc_settings.get("hybrid_mode", True),
            fallback_to_classical=pqc_settings.get("fallback_to_classical", False),
            quantum_safe_only=pqc_settings.get("quantum_safe_only", False),
            # Performance settings
            hardware_acceleration=pqc_settings.get("hardware_acceleration", True),
            key_cache_size=pqc_settings.get("key_cache_size", 2000),
            batch_operations=pqc_settings.get("batch_operations", True),
            # Security settings
            require_pqc_for_new_connections=pqc_settings.get(
                "require_pqc_for_new_connections", True
            ),
            min_security_level=pqc_settings.get("min_security_level", 3),
            enable_pqc_for_credentials=pqc_settings.get(
                "enable_pqc_for_credentials", True
            ),
            enable_pqc_for_proofs=pqc_settings.get("enable_pqc_for_proofs", True),
            # Wallet integration
            use_askar_anoncreds=pqc_settings.get("use_askar_anoncreds", True),
            pqc_key_derivation=pqc_settings.get("pqc_key_derivation", True),
            # Demo integration
            enable_demo_mode=demo_mode,
            demo_algorithms=pqc_settings.get("demo_algorithms", None),
            # Algorithm lists
            enabled_kem_algorithms=pqc_settings.get("enabled_kem_algorithms", None),
            enabled_sig_algorithms=pqc_settings.get("enabled_sig_algorithms", None),
            enabled_hash_sig_algorithms=pqc_settings.get(
                "enabled_hash_sig_algorithms", None
            ),
        )

    def validate(self) -> None:
        """Validate configuration settings for production deployment.

        Raises:
            ValueError: If configuration is invalid
        """
        # Validate default algorithms are in enabled lists
        if self.default_kem_algorithm not in self.enabled_kem_algorithms:
            raise ValueError(
                f"Default KEM algorithm '{self.default_kem_algorithm}' "
                f"not in enabled algorithms: {self.enabled_kem_algorithms}"
            )

        if self.default_sig_algorithm not in self.enabled_sig_algorithms:
            raise ValueError(
                f"Default signature algorithm '{self.default_sig_algorithm}' "
                f"not in enabled algorithms: {self.enabled_sig_algorithms}"
            )

        # Validate security level
        if not 1 <= self.min_security_level <= 5:
            raise ValueError(
                f"Security level must be between 1-5, got: {self.min_security_level}"
            )

        # Production security checks
        if self.min_security_level < 3 and not self.enable_demo_mode:
            LOGGER.warning(
                "⚠️  Security level < 3 not recommended for production. "
                "Consider using Level 3+ algorithms."
            )

        # Validate wallet configuration
        if self.use_askar_anoncreds and self.quantum_safe_only:
            LOGGER.info("✅ Using Askar-AnonCreds with quantum-safe mode")

        LOGGER.info("✅ PQCrypto_FM configuration validated successfully")

    def get_demo_config(self, agent_name: str) -> Dict[str, str]:
        """Get demo-specific configuration for an agent.

        Args:
            agent_name: Name of the demo agent (faber, alice, acme, performance)

        Returns:
            Demo configuration dictionary
        """
        if not self.enable_demo_mode:
            return {}

        agent_alg = self.demo_algorithms.get(
            agent_name.lower(), self.default_sig_algorithm
        )

        return {
            "agent_name": agent_name,
            "primary_algorithm": agent_alg,
            "kem_algorithm": self.default_kem_algorithm,
            "sig_algorithm": agent_alg,
            "demo_mode": True,
            "quantum_safe": True,
        }


# Algorithm security level mappings (NIST standards)
ALGORITHM_SECURITY_LEVELS = {
    # KEM algorithms (FIPS 203 - ML-KEM)
    "Kyber512": 1,
    "Kyber768": 3,
    "Kyber1024": 5,
    # Signature algorithms (FIPS 204 - ML-DSA)
    "Dilithium2": 1,
    "Dilithium3": 3,
    "Dilithium5": 5,
    # Hash-based signatures (FIPS 205 - SLH-DSA)
    "SPHINCS+-SHAKE-128s-simple": 1,
    "SPHINCS+-SHA2-128s-simple": 1,
    "SPHINCS+-SHAKE-192s-simple": 3,
    "SPHINCS+-SHA2-192s-simple": 3,
    "SPHINCS+-SHAKE-256s-simple": 5,
    "SPHINCS+-SHA2-256s-simple": 5,
    # Additional algorithms for completeness
    "SPHINCS+-SHAKE-128f-simple": 1,
    "SPHINCS+-SHA2-128f-simple": 1,
    "SPHINCS+-SHAKE-192f-simple": 3,
    "SPHINCS+-SHA2-192f-simple": 3,
    "SPHINCS+-SHAKE-256f-simple": 5,
    "SPHINCS+-SHA2-256f-simple": 5,
}


def get_algorithm_security_level(algorithm: str) -> int:
    """Get the NIST security level for a given algorithm.

    Args:
        algorithm: Algorithm name

    Returns:
        Security level (1-5)

    Raises:
        ValueError: If algorithm is unknown
    """
    level = ALGORITHM_SECURITY_LEVELS.get(algorithm)
    if level is None:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    return level


def is_algorithm_production_ready(algorithm: str) -> bool:
    """Check if algorithm is ready for production use.

    Args:
        algorithm: Algorithm name

    Returns:
        True if production-ready
    """
    return algorithm in [
        "Kyber768",
        "Kyber1024",  # ML-KEM production ready
        "Dilithium3",
        "Dilithium5",  # ML-DSA production ready
        "SPHINCS+-SHAKE-192s-simple",  # SLH-DSA level 3+
        "SPHINCS+-SHA2-192s-simple",
        "SPHINCS+-SHAKE-256s-simple",
        "SPHINCS+-SHA2-256s-simple",
    ]

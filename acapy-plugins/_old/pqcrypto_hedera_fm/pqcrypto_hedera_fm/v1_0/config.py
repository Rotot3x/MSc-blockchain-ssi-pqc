"""Configuration for PQCrypto Hedera FM Plugin."""

import logging
from typing import Dict, Any, Optional

LOGGER = logging.getLogger(__name__)


class PQCHederaConfig:
    """Configuration class for PQCrypto Hedera FM Plugin."""

    # Default settings
    DEFAULT_NETWORK = "testnet"
    DEFAULT_SIGNATURE_ALGORITHM = "ML-DSA-65"
    DEFAULT_KEM_ALGORITHM = "ML-KEM-768"
    DEFAULT_DID_METHOD = "did:hedera-pqc"

    def __init__(self, settings: Dict[str, Any]):
        """Initialize PQCrypto Hedera FM configuration.

        Args:
            settings: ACA-Py settings dictionary
        """
        self.settings = settings

        # Core Hedera settings
        self.network = self._get_str("pqcrypto_hedera_fm.network", self.DEFAULT_NETWORK)
        self.operator_id = self._get_str("pqcrypto_hedera_fm.operator_id", "")
        self.operator_key = self._get_str("pqcrypto_hedera_fm.operator_key", "")

        # Hedera endpoints (auto-configured based on network)
        self.node_endpoints = self._get_node_endpoints()
        self.mirror_node_url = self._get_mirror_node_url()

        # PQC algorithm settings
        self.signature_algorithm = self._get_str(
            "pqcrypto_hedera_fm.signature_algorithm",
            self.DEFAULT_SIGNATURE_ALGORITHM
        )
        self.kem_algorithm = self._get_str(
            "pqcrypto_hedera_fm.kem_algorithm",
            self.DEFAULT_KEM_ALGORITHM
        )

        # DID settings
        self.did_method = self._get_str(
            "pqcrypto_hedera_fm.did_method",
            self.DEFAULT_DID_METHOD
        )
        self.did_namespace = f"{self.did_method}:{self.network}"

        # Pure PQC settings (no hybrid mode)
        self.enable_pure_pqc = self._get_bool("pqcrypto_hedera_fm.enable_pure_pqc", True)
        self.disable_classical_crypto = self._get_bool("pqcrypto_hedera_fm.disable_classical_crypto", True)

        # Smart contract settings
        self.schema_contract_id = self._get_str("pqcrypto_hedera_fm.schema_contract_id", "")
        self.creddef_contract_id = self._get_str("pqcrypto_hedera_fm.creddef_contract_id", "")
        self.revocation_contract_id = self._get_str("pqcrypto_hedera_fm.revocation_contract_id", "")

        # Performance settings
        self.consensus_timeout = self._get_int("pqcrypto_hedera_fm.consensus_timeout", 30)
        self.retry_attempts = self._get_int("pqcrypto_hedera_fm.retry_attempts", 3)
        self.cache_ttl = self._get_int("pqcrypto_hedera_fm.cache_ttl", 300)

        # Security settings
        self.require_pqc_signatures = self._get_bool("pqcrypto_hedera_fm.require_pqc_signatures", True)
        self.verify_consensus_proofs = self._get_bool("pqcrypto_hedera_fm.verify_consensus_proofs", True)
        self.enable_audit_logging = self._get_bool("pqcrypto_hedera_fm.enable_audit_logging", True)

        # Debug settings
        self.debug_mode = self._get_bool("pqcrypto_hedera_fm.debug_mode", False)
        self.log_transactions = self._get_bool("pqcrypto_hedera_fm.log_transactions", False)
        self.enable_metrics = self._get_bool("pqcrypto_hedera_fm.enable_metrics", True)

        # Validate configuration
        self._validate_config()

        LOGGER.info(f"PQCrypto Hedera FM Config initialized: {self.get_summary()}")

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

    def _get_node_endpoints(self) -> list:
        """Get Hedera node endpoints based on network."""
        if self.network == "mainnet":
            return [
                "35.237.200.180:50211",
                "35.186.191.247:50211",
                "35.192.2.25:50211",
            ]
        elif self.network == "testnet":
            return [
                "50.18.132.211:50211",
                "52.168.76.241:50211",
                "54.70.192.33:50211",
            ]
        elif self.network == "previewnet":
            return [
                "35.199.161.108:50211",
                "35.203.82.240:50211",
                "35.197.192.225:50211",
            ]
        else:  # local
            return ["127.0.0.1:50211"]

    def _get_mirror_node_url(self) -> str:
        """Get mirror node URL based on network."""
        if self.network == "mainnet":
            return "https://mainnet-public.mirrornode.hedera.com"
        elif self.network == "testnet":
            return "https://testnet.mirrornode.hedera.com"
        elif self.network == "previewnet":
            return "https://previewnet.mirrornode.hedera.com"
        else:  # local
            return "http://localhost:5551"

    def _validate_config(self):
        """Validate configuration."""
        if not self.operator_id and self.network != "local":
            raise ValueError("operator_id is required for non-local networks")

        if not self.operator_key and self.network != "local":
            raise ValueError("operator_key is required for non-local networks")

        if self.signature_algorithm not in ["ML-DSA-65", "ML-DSA-44", "ML-DSA-87"]:
            raise ValueError(f"Unsupported signature algorithm: {self.signature_algorithm}")

        if self.kem_algorithm not in ["ML-KEM-768", "ML-KEM-512", "ML-KEM-1024"]:
            raise ValueError(f"Unsupported KEM algorithm: {self.kem_algorithm}")

        if not self.enable_pure_pqc:
            raise ValueError("Pure PQC mode is required - hybrid mode not supported")

    def get_summary(self) -> str:
        """Get configuration summary."""
        return (
            f"Network={self.network}, "
            f"Sig={self.signature_algorithm}, "
            f"KEM={self.kem_algorithm}, "
            f"DID={self.did_method}, "
            f"PurePQC={self.enable_pure_pqc}"
        )

    def get_hedera_network_name(self) -> str:
        """Get Hedera network name for SDK."""
        network_map = {
            "mainnet": "mainnet",
            "testnet": "testnet",
            "previewnet": "previewnet",
            "local": "localhost"
        }
        return network_map.get(self.network, "testnet")

    def is_local_network(self) -> bool:
        """Check if using local network."""
        return self.network == "local"

    def get_did_namespace(self) -> str:
        """Get full DID namespace."""
        return self.did_namespace

    def requires_operator_credentials(self) -> bool:
        """Check if operator credentials are required."""
        return not self.is_local_network()

    def get_contract_ids(self) -> Dict[str, str]:
        """Get all contract IDs."""
        return {
            "schema": self.schema_contract_id,
            "creddef": self.creddef_contract_id,
            "revocation": self.revocation_contract_id,
        }
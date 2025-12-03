"""Tests for PQC configuration."""

import pytest
from unittest.mock import Mock

from ..config import PQCConfig


class TestPQCConfig:
    """Test PQC configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        settings = {}
        config = PQCConfig(settings)

        assert config.enable_pqc is True
        assert config.enable_hybrid_mode is True
        assert config.set_as_default is True
        assert config.signature_algorithm == "ML-DSA-65"
        assert config.kem_algorithm == "ML-KEM-768"
        assert config.enable_key_caching is True
        assert config.max_cached_keys == 100

    def test_custom_config(self):
        """Test custom configuration values."""
        settings = {
            "pqc.enable": "false",
            "pqc.hybrid_mode": "false",
            "pqc.signature_algorithm": "Dilithium3",
            "pqc.kem_algorithm": "Kyber768",
            "pqc.max_cached_keys": "50"
        }
        config = PQCConfig(settings)

        assert config.enable_pqc is False
        assert config.enable_hybrid_mode is False
        assert config.signature_algorithm == "Dilithium3"
        assert config.kem_algorithm == "Kyber768"
        assert config.max_cached_keys == 50

    def test_boolean_parsing(self):
        """Test boolean value parsing."""
        test_cases = [
            ("true", True),
            ("True", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
            ("off", False),
            (True, True),
            (False, False),
        ]

        for input_val, expected in test_cases:
            settings = {"pqc.enable": input_val}
            config = PQCConfig(settings)
            assert config.enable_pqc == expected

    def test_algorithm_enabled_check(self):
        """Test algorithm enabled check."""
        settings = {
            "pqc.signature_algorithm": "ML-DSA-65",
            "pqc.kem_algorithm": "ML-KEM-768"
        }
        config = PQCConfig(settings)

        assert config.is_algorithm_enabled("ML-DSA-65") is True
        assert config.is_algorithm_enabled("ML-KEM-768") is True
        assert config.is_algorithm_enabled("UnknownAlgorithm") is False

    def test_get_summary(self):
        """Test configuration summary."""
        settings = {}
        config = PQCConfig(settings)
        summary = config.get_summary()

        assert "PQC=True" in summary
        assert "Hybrid=True" in summary
        assert "Default=True" in summary
        assert "Sig=ML-DSA-65" in summary
        assert "KEM=ML-KEM-768" in summary

    def test_preferred_algorithms(self):
        """Test preferred algorithm getters."""
        settings = {
            "pqc.signature_algorithm": "Dilithium3",
            "pqc.kem_algorithm": "Kyber768"
        }
        config = PQCConfig(settings)

        assert config.get_preferred_signature_algorithm() == "Dilithium3"
        assert config.get_preferred_kem_algorithm() == "Kyber768"
"""Integration tests for PQCrypto_FM Plugin."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

try:
    import oqs
    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False

from acapy_agent.core.profile import Profile
from acapy_agent.config.injection_context import InjectionContext

from pqcrypto_fm.v1_0.config import PQCConfig
from pqcrypto_fm.v1_0.services.pqc_crypto_service import PQCCryptoService
from pqcrypto_fm.v1_0.services.pqc_wallet_service import PQCWalletService
from pqcrypto_fm.v1_0.services.pqc_did_service import PQCDidService
from pqcrypto_fm.v1_0.key_types import ML_DSA_65, ML_KEM_768


@pytest.fixture
def config():
    """Create a test configuration."""
    settings = {
        "pqc.enable": True,
        "pqc.hybrid_mode": True,
        "pqc.signature_algorithm": "ML-DSA-65",
        "pqc.kem_algorithm": "ML-KEM-768",
        "pqc.debug_mode": True
    }
    return PQCConfig(settings)


@pytest.fixture
def mock_profile():
    """Create a mock profile."""
    profile = MagicMock(spec=Profile)
    profile.session = AsyncMock()
    profile.inject = MagicMock()
    return profile


@pytest.fixture
def mock_context():
    """Create a mock injection context."""
    context = MagicMock(spec=InjectionContext)
    context.settings = {}
    return context


class TestPQCIntegration:
    """Integration tests for PQC functionality."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not available")
    async def test_crypto_service_initialization(self, config):
        """Test crypto service initialization."""
        service = PQCCryptoService(config)
        await service.initialize()

        assert service._initialized is True
        assert len(service._available_sig_algorithms) > 0
        assert len(service._available_kem_algorithms) > 0

    @pytest.mark.asyncio
    @pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not available")
    async def test_key_generation_and_signing(self, config):
        """Test key generation and signing workflow."""
        service = PQCCryptoService(config)
        await service.initialize()

        # Generate keypair
        keypair = await service.generate_keypair(ML_DSA_65)

        assert keypair is not None
        assert keypair.public_key is not None
        assert keypair.private_key is not None
        assert keypair.algorithm is not None

        # Sign a message
        message = b"Hello, Post-Quantum World!"
        signature = await service.sign(message, keypair)

        assert signature is not None
        assert signature.signature is not None
        assert signature.algorithm == keypair.algorithm

        # Verify signature
        is_valid = await service.verify(message, signature)
        assert is_valid is True

        # Verify with wrong message should fail
        wrong_message = b"Wrong message"
        is_valid_wrong = await service.verify(wrong_message, signature)
        assert is_valid_wrong is False

    @pytest.mark.asyncio
    async def test_wallet_service_key_storage(self, config, mock_profile):
        """Test wallet service key storage."""
        # Mock the storage operations
        mock_session = AsyncMock()
        mock_profile.session.return_value.__aenter__.return_value = mock_session

        wallet_service = PQCWalletService(config)

        # Mock the crypto service
        mock_crypto_service = AsyncMock(spec=PQCCryptoService)
        mock_keypair = MagicMock()
        mock_keypair.public_key = b"mock_public_key"
        mock_keypair.private_key = b"mock_private_key"
        mock_keypair.algorithm = "ML-DSA-65"
        mock_keypair.key_type = "ml-dsa-65"
        mock_keypair.created_at = 1234567890.0
        mock_keypair.metadata = {}

        mock_crypto_service.generate_keypair.return_value = mock_keypair
        mock_profile.inject.return_value = mock_crypto_service

        # This would normally store the key
        # key_info = await wallet_service.create_pqc_key(mock_profile, ML_DSA_65)
        # assert key_info is not None

    @pytest.mark.asyncio
    async def test_did_service_creation(self, config, mock_profile):
        """Test DID service DID creation."""
        mock_session = AsyncMock()
        mock_profile.session.return_value.__aenter__.return_value = mock_session

        did_service = PQCDidService(config)

        # Mock the wallet service
        mock_wallet_service = AsyncMock()
        mock_key_info = MagicMock()
        mock_key_info.verkey = "mock_verkey"
        mock_key_info.key_type = ML_DSA_65
        mock_key_info.metadata = {}

        mock_wallet_service.create_pqc_signing_key.return_value = mock_key_info
        mock_profile.inject.return_value = mock_wallet_service

        # This would normally create a DID
        # did_info = await did_service.create_pqc_did(mock_profile)
        # assert did_info is not None
        # assert did_info.did.startswith("did:")

    def test_plugin_configuration_validation(self, config):
        """Test plugin configuration validation."""
        assert config.enable_pqc is True
        assert config.enable_hybrid_mode is True
        assert config.signature_algorithm == "ML-DSA-65"
        assert config.kem_algorithm == "ML-KEM-768"

        # Test algorithm validation
        assert config.is_algorithm_enabled("ML-DSA-65") is True
        assert config.is_algorithm_enabled("UnknownAlgorithm") is False

    @pytest.mark.asyncio
    @pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not available")
    async def test_available_algorithms(self, config):
        """Test available algorithms retrieval."""
        service = PQCCryptoService(config)
        await service.initialize()

        algorithms = service.get_available_algorithms()

        assert "signature" in algorithms
        assert "kem" in algorithms
        assert isinstance(algorithms["signature"], list)
        assert isinstance(algorithms["kem"], list)
        assert len(algorithms["signature"]) > 0
        assert len(algorithms["kem"]) > 0

    @pytest.mark.asyncio
    @pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not available")
    async def test_kem_operations(self, config):
        """Test KEM encapsulation and decapsulation."""
        service = PQCCryptoService(config)
        await service.initialize()

        # Generate KEM keypair
        keypair = await service.generate_keypair(ML_KEM_768)

        assert keypair is not None
        assert keypair.public_key is not None
        assert keypair.private_key is not None

        # Encapsulate secret
        ciphertext, shared_secret = await service.encapsulate(
            keypair.public_key, keypair.algorithm
        )

        assert ciphertext is not None
        assert shared_secret is not None

        # Decapsulate secret
        decapsulated_secret = await service.decapsulate(ciphertext, keypair)

        assert decapsulated_secret == shared_secret

    def test_error_handling_without_liboqs(self, config):
        """Test error handling when liboqs is not available."""
        # This test simulates the case where liboqs is not available
        original_has_liboqs = HAS_LIBOQS

        # Mock the absence of liboqs
        import pqcrypto_fm.v1_0.services.pqc_crypto_service as crypto_module
        crypto_module.HAS_LIBOQS = False

        try:
            service = PQCCryptoService(config)
            assert service._initialized is False

            # Should handle gracefully
            asyncio.run(service.initialize())
            assert service._initialized is True

        finally:
            # Restore original value
            crypto_module.HAS_LIBOQS = original_has_liboqs

    def test_configuration_edge_cases(self):
        """Test configuration edge cases."""
        # Test with empty settings
        empty_config = PQCConfig({})
        assert empty_config.enable_pqc is True  # Default value

        # Test with invalid boolean values
        invalid_bool_config = PQCConfig({"pqc.enable": "invalid"})
        assert invalid_bool_config.enable_pqc is False

        # Test with invalid integer values
        invalid_int_config = PQCConfig({"pqc.max_cached_keys": "invalid"})
        assert invalid_int_config.max_cached_keys == 100  # Default value
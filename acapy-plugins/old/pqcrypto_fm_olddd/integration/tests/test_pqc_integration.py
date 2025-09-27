"""
Integration Tests for PQC Plugin

Comprehensive tests for Post-Quantum Cryptography integration in ACA-Py.
"""

import pytest
from aries_cloudagent.core.in_memory import InMemoryProfile
from pqc_acapy_plugin.v1_0.config import PQCConfig
from pqc_acapy_plugin.v1_0.services.pqc_crypto_service import PQCCryptoService
from pqc_acapy_plugin.v1_0.services.pqc_key_service import PQCKeyService


class TestPQCIntegration:
    """Integration tests for PQC functionality."""

    @pytest.fixture
    async def profile(self):
        """Create test profile."""
        profile = InMemoryProfile.test_profile()
        yield profile
        await profile.close()

    @pytest.fixture
    def pqc_config(self):
        """Create test PQC configuration."""
        return PQCConfig(
            default_kem_algorithm="Kyber768",
            default_sig_algorithm="Dilithium3",
            hybrid_mode=True,
            enabled_kem_algorithms=["Kyber512", "Kyber768", "Kyber1024"],
            enabled_sig_algorithms=["Dilithium2", "Dilithium3", "Dilithium5"],
        )

    @pytest.fixture
    async def crypto_service(self, pqc_config):
        """Create and initialize crypto service."""
        service = PQCCryptoService(pqc_config)
        try:
            await service.initialize()
            yield service
        except RuntimeError:
            # Skip tests if liboqs not available
            pytest.skip("liboqs-python not available")

    @pytest.fixture
    async def key_service(self, crypto_service):
        """Create key service."""
        return PQCKeyService(crypto_service)

    @pytest.mark.asyncio
    async def test_kem_key_generation(self, profile, key_service):
        """Test KEM key pair generation."""
        async with profile.session() as session:
            # Generate Kyber768 key pair
            key_record = await key_service.create_key_pair(
                session, "kem", "Kyber768", "test-kem-1"
            )

            assert key_record is not None
            assert key_record.key_type == "kem"
            assert key_record.algorithm == "Kyber768"
            assert key_record.key_id == "test-kem-1"
            assert len(key_record.public_key) > 0
            assert len(key_record.private_key) > 0

    @pytest.mark.asyncio
    async def test_sig_key_generation(self, profile, key_service):
        """Test signature key pair generation."""
        async with profile.session() as session:
            # Generate Dilithium3 key pair
            key_record = await key_service.create_key_pair(
                session, "sig", "Dilithium3", "test-sig-1"
            )

            assert key_record is not None
            assert key_record.key_type == "sig"
            assert key_record.algorithm == "Dilithium3"
            assert key_record.key_id == "test-sig-1"
            assert len(key_record.public_key) > 0
            assert len(key_record.private_key) > 0

    @pytest.mark.asyncio
    async def test_hybrid_key_generation(self, profile, key_service):
        """Test hybrid key pair generation."""
        async with profile.session() as session:
            # Generate hybrid key pair
            key_pairs = await key_service.create_hybrid_key_pair(
                session, "Kyber768", "test-hybrid-1"
            )

            assert "pqc" in key_pairs
            assert "classical" in key_pairs

            pqc_key = key_pairs["pqc"]
            classical_key = key_pairs["classical"]

            # Verify PQC key
            assert pqc_key.key_type == "kem"
            assert pqc_key.algorithm == "Kyber768"
            assert pqc_key.metadata.get("hybrid") is True

            # Verify classical key
            assert classical_key.key_type == "classical_ecdh"
            assert classical_key.algorithm == "ECDH-P256"
            assert classical_key.metadata.get("hybrid") is True

            # Verify keys are paired
            assert pqc_key.metadata.get("paired_with") == classical_key.record_id
            assert classical_key.metadata.get("paired_with") == pqc_key.record_id

    @pytest.mark.asyncio
    async def test_kem_encrypt_decrypt(self, crypto_service):
        """Test KEM encapsulation and decapsulation."""
        # Generate key pair
        key_pair = crypto_service.generate_kem_keypair("Kyber768")

        # Test encapsulation
        ciphertext, shared_secret = crypto_service.kem_encapsulate(
            key_pair.public_key, "Kyber768"
        )

        # Test decapsulation
        decrypted_secret = crypto_service.kem_decapsulate(
            ciphertext, key_pair.private_key, "Kyber768"
        )

        assert shared_secret == decrypted_secret
        assert len(shared_secret) > 0
        assert len(ciphertext) > 0

    @pytest.mark.asyncio
    async def test_signature_sign_verify(self, crypto_service):
        """Test PQC signing and verification."""
        message = b"Hello, Post-Quantum World!"

        # Generate key pair
        key_pair = crypto_service.generate_sig_keypair("Dilithium3")

        # Test signing
        signature = crypto_service.sign_message(
            message, key_pair.private_key, "Dilithium3"
        )

        # Test verification
        valid = crypto_service.verify_signature(
            message, signature, key_pair.public_key, "Dilithium3"
        )

        assert valid is True
        assert len(signature) > 0

        # Test with wrong message
        invalid = crypto_service.verify_signature(
            b"Wrong message", signature, key_pair.public_key, "Dilithium3"
        )

        assert invalid is False

    @pytest.mark.asyncio
    async def test_hybrid_key_agreement(self, crypto_service):
        """Test hybrid key agreement."""
        # Generate PQC key pairs for both parties
        alice_pqc = crypto_service.generate_kem_keypair("Kyber768")
        bob_pqc = crypto_service.generate_kem_keypair("Kyber768")

        # Generate classical key pairs
        alice_classical_pub, alice_classical_priv = (
            crypto_service.generate_classical_keypair()
        )
        bob_classical_pub, bob_classical_priv = (
            crypto_service.generate_classical_keypair()
        )

        # Alice performs hybrid key agreement with Bob
        alice_shared = crypto_service.perform_hybrid_key_agreement(
            bob_pqc.public_key,
            bob_classical_pub,
            alice_pqc.private_key,
            alice_classical_priv,
            "Kyber768",
        )

        assert alice_shared.pqc_secret is not None
        assert alice_shared.classical_secret is not None
        assert alice_shared.combined_secret is not None
        assert len(alice_shared.combined_secret) == 32  # 256-bit combined secret

    @pytest.mark.asyncio
    async def test_hybrid_encryption(self, crypto_service):
        """Test hybrid encryption/decryption."""
        plaintext = b"Secret quantum-safe message!"

        # Generate shared secret (normally from key agreement)
        import os

        shared_secret = os.urandom(32)

        # Encrypt
        ciphertext, nonce = crypto_service.hybrid_encrypt(plaintext, shared_secret)

        # Decrypt
        decrypted = crypto_service.hybrid_decrypt(ciphertext, nonce, shared_secret)

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_key_storage_retrieval(self, profile, key_service):
        """Test key storage and retrieval."""
        async with profile.session() as session:
            # Create multiple keys
            kem_key = await key_service.create_key_pair(
                session, "kem", "Kyber768", "test-storage-kem"
            )

            sig_key = await key_service.create_key_pair(
                session, "sig", "Dilithium3", "test-storage-sig"
            )

            # Test retrieval by ID
            retrieved_kem = await key_service.get_key_record(session, kem_key.record_id)
            assert retrieved_kem is not None
            assert retrieved_kem.key_id == "test-storage-kem"

            # Test find by type
            kem_keys = await key_service.find_key_records(session, key_type="kem")
            assert len(kem_keys) >= 1
            assert any(k.record_id == kem_key.record_id for k in kem_keys)

            # Test find by algorithm
            dilithium_keys = await key_service.find_key_records(
                session, algorithm="Dilithium3"
            )
            assert len(dilithium_keys) >= 1
            assert any(k.record_id == sig_key.record_id for k in dilithium_keys)

    @pytest.mark.asyncio
    async def test_default_key_management(self, profile, key_service):
        """Test default key management."""
        async with profile.session() as session:
            # Create two Kyber768 keys
            key1 = await key_service.create_key_pair(session, "kem", "Kyber768", "key1")

            key2 = await key_service.create_key_pair(session, "kem", "Kyber768", "key2")

            # Set key1 as default
            success = await key_service.set_default_key(session, key1.record_id)
            assert success is True

            # Verify key1 is default
            default_key = await key_service.get_default_key_for_algorithm(
                session, "kem", "Kyber768"
            )
            assert default_key is not None
            assert default_key.record_id == key1.record_id

            # Set key2 as default
            await key_service.set_default_key(session, key2.record_id)

            # Verify key2 is now default
            default_key = await key_service.get_default_key_for_algorithm(
                session, "kem", "Kyber768"
            )
            assert default_key.record_id == key2.record_id

    @pytest.mark.asyncio
    async def test_key_statistics(self, profile, key_service):
        """Test key statistics."""
        async with profile.session() as session:
            # Create various keys
            await key_service.create_key_pair(session, "kem", "Kyber768")
            await key_service.create_key_pair(session, "kem", "Kyber1024")
            await key_service.create_key_pair(session, "sig", "Dilithium3")
            await key_service.create_hybrid_key_pair(session, "Kyber768")

            # Get statistics
            stats = await key_service.get_key_statistics(session)

            assert stats["total_keys"] >= 5  # 3 individual + 2 from hybrid pair
            assert "kem" in stats["by_type"]
            assert "sig" in stats["by_type"]
            assert "classical_ecdh" in stats["by_type"]
            assert "Kyber768" in stats["by_algorithm"]
            assert "Dilithium3" in stats["by_algorithm"]
            assert stats["hybrid_pairs"] >= 1

    @pytest.mark.asyncio
    async def test_algorithm_availability(self, crypto_service):
        """Test algorithm availability checking."""
        algorithms = crypto_service.get_available_algorithms()

        assert "kem" in algorithms
        assert "signature" in algorithms
        assert "enabled_kem" in algorithms
        assert "enabled_sig" in algorithms

        # Should have some algorithms available
        assert len(algorithms["kem"]) > 0
        assert len(algorithms["signature"]) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self, crypto_service, profile, key_service):
        """Test error handling for invalid operations."""

        # Test invalid algorithm
        with pytest.raises(ValueError):
            crypto_service.generate_kem_keypair("InvalidAlgorithm")

        # Test invalid key type
        async with profile.session() as session:
            with pytest.raises(ValueError):
                await key_service.create_key_pair(session, "invalid_type", "Kyber768")

        # Test non-existent key retrieval
        async with profile.session() as session:
            result = await key_service.get_key_record(session, "non-existent-id")
            assert result is None

    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        config = PQCConfig()
        config.validate()  # Should not raise

        # Invalid security level
        config.min_security_level = 10
        with pytest.raises(ValueError):
            config.validate()

        # Default algorithm not in enabled list
        config.min_security_level = 1
        config.enabled_kem_algorithms = ["Kyber512"]
        config.default_kem_algorithm = "Kyber1024"
        with pytest.raises(ValueError):
            config.validate()

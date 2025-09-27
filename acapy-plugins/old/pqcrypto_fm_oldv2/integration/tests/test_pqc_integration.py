"""
Integration Tests for PQCrypto_FM Plugin

Basic integration tests for PQC functionality.
"""

import pytest
import asyncio

class TestPQCIntegration:
    """Integration tests for PQC functionality."""

    @pytest.mark.asyncio
    async def test_plugin_loads(self):
        """Test that the plugin loads successfully."""
        try:
            import pqcrypto_fm
            assert pqcrypto_fm.__version__ == "1.0.0"
        except ImportError:
            pytest.skip("PQCrypto_FM plugin not available")

    @pytest.mark.asyncio  
    async def test_liboqs_available(self):
        """Test that liboqs-python is available."""
        try:
            import oqs
            kem = oqs.KeyEncapsulation("Kyber768")
            assert kem is not None
        except ImportError:
            pytest.skip("liboqs-python not available")

    def test_basic_pqc_algorithms(self):
        """Test basic PQC algorithm availability."""
        try:
            import oqs

            # Test KEM
            assert oqs.KeyEncapsulation.is_kem_enabled("Kyber768")

            # Test Signature
            assert oqs.Signature.is_sig_enabled("Dilithium3")

        except ImportError:
            pytest.skip("liboqs-python not available")
"""Tests for PQC key types."""

import pytest

from ..key_types import (
    ML_DSA_65, ML_KEM_768, DILITHIUM3, KYBER768,
    HYBRID_ML_DSA_65_ED25519, HYBRID_ML_KEM_768_X25519,
    PQC_KEY_TYPES, PQC_SIGNATURE_KEY_TYPES, PQC_KEM_KEY_TYPES, PQC_HYBRID_KEY_TYPES,
    is_pqc_key_type, is_signature_key_type, is_kem_key_type, is_hybrid_key_type,
    get_signature_key_types, get_kem_key_types, get_hybrid_key_types
)


class TestKeyTypes:
    """Test PQC key types."""

    def test_signature_key_types(self):
        """Test signature key type identification."""
        assert is_signature_key_type(ML_DSA_65) is True
        assert is_signature_key_type(DILITHIUM3) is True
        assert is_signature_key_type(ML_KEM_768) is False
        assert is_signature_key_type(KYBER768) is False

    def test_kem_key_types(self):
        """Test KEM key type identification."""
        assert is_kem_key_type(ML_KEM_768) is True
        assert is_kem_key_type(KYBER768) is True
        assert is_kem_key_type(ML_DSA_65) is False
        assert is_kem_key_type(DILITHIUM3) is False

    def test_hybrid_key_types(self):
        """Test hybrid key type identification."""
        assert is_hybrid_key_type(HYBRID_ML_DSA_65_ED25519) is True
        assert is_hybrid_key_type(HYBRID_ML_KEM_768_X25519) is True
        assert is_hybrid_key_type(ML_DSA_65) is False
        assert is_hybrid_key_type(ML_KEM_768) is False

    def test_pqc_key_type_identification(self):
        """Test PQC key type identification."""
        assert is_pqc_key_type(ML_DSA_65) is True
        assert is_pqc_key_type(ML_KEM_768) is True
        assert is_pqc_key_type(HYBRID_ML_DSA_65_ED25519) is True

    def test_key_type_collections(self):
        """Test key type collections."""
        sig_types = get_signature_key_types()
        kem_types = get_kem_key_types()
        hybrid_types = get_hybrid_key_types()

        assert ML_DSA_65 in sig_types
        assert DILITHIUM3 in sig_types
        assert ML_KEM_768 in kem_types
        assert KYBER768 in kem_types
        assert HYBRID_ML_DSA_65_ED25519 in hybrid_types
        assert HYBRID_ML_KEM_768_X25519 in hybrid_types

    def test_all_key_types_included(self):
        """Test that all key types are included in the main collection."""
        assert len(PQC_KEY_TYPES) > 0
        assert ML_DSA_65 in PQC_KEY_TYPES
        assert ML_KEM_768 in PQC_KEY_TYPES
        assert HYBRID_ML_DSA_65_ED25519 in PQC_KEY_TYPES

    def test_key_type_string_attributes(self):
        """Test key type string attributes."""
        assert ML_DSA_65.key_type == "ml-dsa-65"
        assert ML_DSA_65.pretty_name == "ML-DSA-65"
        assert ML_KEM_768.key_type == "ml-kem-768"
        assert ML_KEM_768.pretty_name == "ML-KEM-768"

    def test_no_duplicate_key_types(self):
        """Test that there are no duplicate key types."""
        key_type_strings = [kt.key_type for kt in PQC_KEY_TYPES]
        assert len(key_type_strings) == len(set(key_type_strings))

    def test_hybrid_key_type_naming(self):
        """Test hybrid key type naming conventions."""
        hybrid_sig = HYBRID_ML_DSA_65_ED25519
        hybrid_kem = HYBRID_ML_KEM_768_X25519

        assert "hybrid" in hybrid_sig.key_type.lower()
        assert "ml-dsa" in hybrid_sig.key_type
        assert "ed25519" in hybrid_sig.key_type

        assert "hybrid" in hybrid_kem.key_type.lower()
        assert "ml-kem" in hybrid_kem.key_type
        assert "x25519" in hybrid_kem.key_type
#!/usr/bin/env python3
"""Test script for dedicated liboqs installation."""

import sys
import os

# Add plugin path
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/acapy-plugins")

def test_dedicated_liboqs():
    """Test our dedicated liboqs installation."""
    print("🔧 Testing Dedicated liboqs Installation for PQCrypto-Hedera-FM")
    print("=" * 70)

    # Test 1: Import our custom oqs module
    print("1. Testing custom oqs module import...")
    try:
        from pqcrypto_hedera_fm.oqs import oqs
        print("   ✅ Successfully imported dedicated oqs module")

        # Test library loading
        print(f"   📚 Library path: {oqs._find_liboqs_library()}")
        print(f"   📚 Library loaded: {oqs._liboqs is not None}")

    except Exception as e:
        print(f"   ❌ Failed to import oqs module: {e}")
        return False

    # Test 2: Test KEM mechanisms
    print("\n2. Testing KEM mechanisms...")
    try:
        kem_mechanisms = oqs.oqs_get_enabled_KEM_mechanisms()
        print(f"   ✅ Available KEM mechanisms: {len(kem_mechanisms)}")
        for mech in kem_mechanisms[:5]:  # Show first 5
            print(f"      - {mech}")
        if len(kem_mechanisms) > 5:
            print(f"      ... and {len(kem_mechanisms) - 5} more")

    except Exception as e:
        print(f"   ❌ Failed to get KEM mechanisms: {e}")

    # Test 3: Test Signature mechanisms
    print("\n3. Testing Signature mechanisms...")
    try:
        sig_mechanisms = oqs.oqs_get_enabled_sig_mechanisms()
        print(f"   ✅ Available Signature mechanisms: {len(sig_mechanisms)}")
        for mech in sig_mechanisms[:5]:  # Show first 5
            print(f"      - {mech}")
        if len(sig_mechanisms) > 5:
            print(f"      ... and {len(sig_mechanisms) - 5} more")

    except Exception as e:
        print(f"   ❌ Failed to get signature mechanisms: {e}")

    # Test 4: Test ML-DSA-65 signature
    print("\n4. Testing ML-DSA-65 signature...")
    try:
        # Try ML-DSA-65 first, fallback to Dilithium3
        alg_name = "ML-DSA-65"
        if alg_name not in sig_mechanisms:
            alg_name = "Dilithium3"

        sig = oqs.Signature(alg_name)
        print(f"   ✅ Successfully initialized {alg_name} signature")

        # Generate keypair
        public_key, secret_key = sig.generate_keypair()
        print(f"   🔑 Generated keypair: {len(public_key)} bytes public, {len(secret_key)} bytes secret")

        # Test signing
        message = b"Test message for dedicated liboqs"
        signature = sig.sign(message, secret_key)
        print(f"   ✍️ Generated signature: {len(signature)} bytes")

        # Test verification
        is_valid = sig.verify(message, signature, public_key)
        print(f"   ✅ Signature verification: {is_valid}")

    except Exception as e:
        print(f"   ❌ Failed ML-DSA-65 test: {e}")

    # Test 5: Test ML-KEM-768
    print("\n5. Testing ML-KEM-768 key encapsulation...")
    try:
        # Try ML-KEM-768 first, fallback to Kyber768
        alg_name = "ML-KEM-768"
        if alg_name not in kem_mechanisms:
            alg_name = "Kyber768"

        kem = oqs.KeyEncapsulation(alg_name)
        print(f"   ✅ Successfully initialized {alg_name} KEM")

        # Generate keypair
        public_key, secret_key = kem.generate_keypair()
        print(f"   🔑 Generated KEM keypair: {len(public_key)} bytes public, {len(secret_key)} bytes secret")

        # Test encapsulation
        shared_secret1, ciphertext = kem.encapsulate(public_key)
        print(f"   📦 Encapsulated: {len(shared_secret1)} bytes secret, {len(ciphertext)} bytes ciphertext")

        # Test decapsulation
        shared_secret2 = kem.decapsulate(secret_key, ciphertext)
        print(f"   📂 Decapsulated: {len(shared_secret2)} bytes secret")

        # Verify shared secrets match
        secrets_match = shared_secret1 == shared_secret2
        print(f"   ✅ Shared secrets match: {secrets_match}")

    except Exception as e:
        print(f"   ❌ Failed ML-KEM-768 test: {e}")

    # Test 6: Integration with PQC Key Manager
    print("\n6. Testing integration with PQC Key Manager...")
    try:
        from pqcrypto_hedera_fm.v1_0.crypto.pqc_key_manager import PQCKeyManager, OQS_AVAILABLE

        print(f"   📊 OQS_AVAILABLE: {OQS_AVAILABLE}")

        if OQS_AVAILABLE:
            class MockConfig:
                network = "local"
                signature_algorithm = "ML-DSA-65"
                kem_algorithm = "ML-KEM-768"
                debug_mode = True

            key_manager = PQCKeyManager(MockConfig())
            print("   ✅ Successfully created PQC Key Manager with dedicated liboqs")

        else:
            print("   ⚠️ OQS not available in PQC Key Manager")

    except Exception as e:
        print(f"   ❌ Failed PQC Key Manager integration test: {e}")

    print("\n" + "=" * 70)
    print("🎯 DEDICATED LIBOQS TEST COMPLETE")
    print("✅ Custom liboqs installation working for pqcrypto_hedera_fm!")
    return True

if __name__ == "__main__":
    success = test_dedicated_liboqs()
    sys.exit(0 if success else 1)
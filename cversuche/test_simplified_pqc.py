#!/usr/bin/env python3
"""
Test Simplified PQC Implementation
===================================

Tests the simplified PQC implementation without acapy-plugins dependencies.
"""

import asyncio
import sys
import os

# Add pqc-lib to path
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/pqc-lib")

async def test_simplified_pqc():
    """Test simplified PQC implementation"""
    print("🧪 Testing Simplified PQC Implementation")
    print("=" * 50)

    success_count = 0
    total_tests = 0

    # Test 1: Central PQC Library
    print("\n1️⃣ Testing Central PQC Library")
    try:
        import pqc_lib
        from pqc_lib import get_pqc_provider, get_ml_dsa_handler, get_ml_kem_encryption

        # Test PQC Provider
        provider = get_pqc_provider()
        algorithms = provider.get_supported_algorithms()
        print(f"   📋 Available algorithms: {algorithms}")

        if provider.is_available() and 'ML-DSA-65' in algorithms:
            keypair = await provider.generate_keypair('ML-DSA-65')
            message = b"Test message for simplified PQC"
            signature = await provider.sign(message, keypair.private_key, 'ML-DSA-65')
            is_valid = await provider.verify(message, signature, keypair.public_key, 'ML-DSA-65')
            print(f"   ✅ ML-DSA-65 signature: {is_valid}")
            if is_valid: success_count += 1
        else:
            print(f"   ⚠️ ML-DSA not available")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 2: ML-KEM Encryption
    print("\n2️⃣ Testing ML-KEM Encryption")
    try:
        encryption = get_ml_kem_encryption()

        if encryption.is_ml_kem_available():
            variants = encryption.get_available_variants()
            print(f"   📋 Available variants: {variants}")

            if variants:
                keypair = await encryption.generate_keypair("ML-KEM-768")
                test_data = b"Test data for ML-KEM encryption" * 10

                encrypted_data = await encryption.encrypt_data(test_data, keypair.public_key)
                decrypted_data = await encryption.decrypt_data(encrypted_data, keypair.private_key)

                success = test_data == decrypted_data
                print(f"   ✅ ML-KEM round-trip: {success}")
                if success: success_count += 1
        else:
            print(f"   ⚠️ ML-KEM not available")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 3: Ed25519 Fallback
    print("\n3️⃣ Testing Ed25519 Fallback")
    try:
        provider = get_pqc_provider()

        if 'ed25519' in provider.get_supported_algorithms():
            keypair = await provider.generate_keypair('ed25519')
            message = b"Test message for Ed25519"
            signature = await provider.sign(message, keypair.private_key, 'ed25519')
            is_valid = await provider.verify(message, signature, keypair.public_key, 'ed25519')
            print(f"   ✅ Ed25519 signature: {is_valid}")
            if is_valid: success_count += 1
        else:
            print(f"   ⚠️ Ed25519 not available")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Summary
    print(f"\n📊 Results: {success_count}/{total_tests} tests passed")
    print(f"Success rate: {(success_count/total_tests)*100:.1f}%")

    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED! Simplified PQC system ready for Docker!")
    elif success_count > 0:
        print("✅ Some tests passed. Core functionality available.")
    else:
        print("❌ All tests failed. Check dependencies.")

    return success_count == total_tests

if __name__ == "__main__":
    asyncio.run(test_simplified_pqc())
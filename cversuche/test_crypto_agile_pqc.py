#!/usr/bin/env python3
"""
Crypto-Agile PQC System Test
============================

Tests the crypto-agile PQC implementation for von-network and indy-tails-server.
"""

import sys
import asyncio
import os

# Add paths for PQC integration
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/acapy-plugins")
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/von-network/server")
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/indy-tails-server")

async def test_crypto_agile_pqc():
    """Test crypto-agile PQC implementation"""
    print("🚀 Crypto-Agile PQC System Test")
    print("=" * 50)

    success_count = 0
    total_tests = 0

    # Test 1: von-network Crypto Provider
    print("\n1️⃣ von-network Crypto Provider")
    try:
        from crypto.pqc_provider import get_crypto_provider

        provider = get_crypto_provider()
        available_algorithms = provider.get_supported_algorithms()
        print(f"   📋 Algorithms: {available_algorithms}")

        # Test ML-DSA-65
        if 'ML-DSA-65' in available_algorithms:
            keypair = await provider.generate_keypair('ML-DSA-65')
            message = b"Test message for crypto-agile von-network"
            signature = await provider.sign(message, keypair.private_key, 'ML-DSA-65')
            is_valid = await provider.verify(message, signature, keypair.public_key, 'ML-DSA-65')
            print(f"   ✅ ML-DSA-65 signature: {is_valid}")
            if is_valid: success_count += 1
        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 2: indy-tails-server PQC Revocation
    print("\n2️⃣ PQC Revocation System")
    try:
        from tails_server.crypto.pqc_revocation import PQCRevocationHandler

        handler = PQCRevocationHandler()
        if handler.is_pqc_available():
            # Create registry
            registry = await handler.create_revocation_registry(
                issuer_did="did:indy:pqc:test-issuer",
                cred_def_id="ML-DSA-65:CL:test-creddef",
                max_cred_num=10,
                signature_algorithm="ML-DSA-65"
            )
            print(f"   ✅ Registry created: {registry.id[:16]}...")

            # Issue and revoke
            await handler.issue_credential(registry.id, "test-cred-001")
            await handler.revoke_credential(registry.id, "test-cred-001", "Test revocation")

            status = await handler.get_credential_status(registry.id, "test-cred-001")
            print(f"   ✅ Credential status: {status}")
            if status == "revoked": success_count += 1
        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 3: ML-KEM Encryption
    print("\n3️⃣ ML-KEM Encryption")
    try:
        from tails_server.crypto.ml_kem_encryption import get_ml_kem_encryption, MLKEMVariant

        encryption = get_ml_kem_encryption()
        if encryption.is_ml_kem_available():
            keypair = await encryption.generate_keypair(MLKEMVariant.ML_KEM_768)
            test_data = b"Sensitive tails data for encryption" * 10

            encrypted_data = await encryption.encrypt_data(test_data, keypair.public_key)
            decrypted_data = await encryption.decrypt_data(encrypted_data, keypair.private_key)

            success = test_data == decrypted_data
            print(f"   ✅ ML-KEM round-trip: {success}")
            if success: success_count += 1
        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 4: Hybrid Cryptography
    print("\n4️⃣ Hybrid Ed25519 + ML-DSA")
    try:
        from crypto.hybrid_crypto import get_hybrid_crypto

        hybrid = get_hybrid_crypto()
        if hybrid.is_available():
            keypair = await hybrid.generate_keypair()
            message = b"Hybrid signature test message"
            signature = await hybrid.sign(message, keypair)
            is_valid = await hybrid.verify(message, signature, keypair)
            print(f"   ✅ Hybrid signature: {is_valid}")
            if is_valid: success_count += 1
        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 5: ML-DSA Handler
    print("\n5️⃣ ML-DSA Handler")
    try:
        from crypto.ml_dsa_handler import get_ml_dsa_handler, MLDSAVariant

        handler = get_ml_dsa_handler()
        if handler.is_ml_dsa_available():
            available = handler.get_available_variants()
            print(f"   📋 ML-DSA variants: {available}")

            if available:
                variant = MLDSAVariant(available[0])
                public_key, private_key, metadata = await handler.generate_keypair(variant)

                message = b"ML-DSA handler test"
                signature, sign_time = await handler.sign(message, private_key, variant)
                is_valid, verify_time = await handler.verify(message, signature, public_key, variant)

                print(f"   ✅ {variant.value}: {is_valid} (sign: {sign_time:.1f}ms)")
                if is_valid: success_count += 1
        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Summary
    print(f"\n📊 Results: {success_count}/{total_tests} tests passed")
    print(f"Success rate: {(success_count/total_tests)*100:.1f}%")

    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED! Crypto-agile PQC system is fully functional!")
    else:
        print("⚠️ Some components need attention.")

    return success_count == total_tests

if __name__ == "__main__":
    asyncio.run(test_crypto_agile_pqc())
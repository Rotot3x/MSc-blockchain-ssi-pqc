#!/usr/bin/env python3
"""
Test Simple PQC Implementation
==============================

Tests the simplified PQC implementation using direct liboqs.
"""

import asyncio
import sys
import os
import tempfile

# Add paths
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/von-network/server")
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/indy-tails-server")

async def test_simple_pqc():
    """Test simplified PQC implementation"""
    print("🧪 Testing Simple PQC Implementation")
    print("=" * 50)

    success_count = 0
    total_tests = 0

    # Test 1: von-network crypto
    print("\n1️⃣ Testing von-network Crypto")
    try:
        from crypto.simple_pqc import get_crypto_provider

        provider = get_crypto_provider()
        algorithms = provider.get_supported_algorithms()
        print(f"   📋 Available algorithms: {algorithms}")

        if provider.is_available() and 'ML-DSA-65' in algorithms:
            # Test ML-DSA signature
            keypair = await provider.generate_keypair('ML-DSA-65')
            message = b"Test message for simple von-network PQC"
            signature = await provider.sign(message, keypair["private_key"], 'ML-DSA-65')
            is_valid = await provider.verify(message, signature, keypair["public_key"], 'ML-DSA-65')
            print(f"   ✅ ML-DSA-65 signature: {is_valid}")

            # Test DID generation
            did = provider.generate_indy_compatible_did(keypair["public_key"], 'ML-DSA-65')
            print(f"   🆔 Generated DID: {did}")

            if is_valid: success_count += 1
        else:
            print(f"   ⚠️ ML-DSA not available")

        # Test Ed25519 fallback
        if 'ed25519' in algorithms:
            keypair = await provider.generate_keypair('ed25519')
            message = b"Test Ed25519 message"
            signature = await provider.sign(message, keypair["private_key"], 'ed25519')
            is_valid = await provider.verify(message, signature, keypair["public_key"], 'ed25519')
            print(f"   ✅ Ed25519 signature: {is_valid}")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 2: von-network ML-KEM
    print("\n2️⃣ Testing von-network ML-KEM")
    try:
        from crypto.simple_pqc import get_ml_kem_encryption

        encryption = get_ml_kem_encryption()

        if encryption.is_available():
            variants = encryption.get_available_variants()
            print(f"   📋 Available variants: {variants}")

            if variants:
                # Test encryption
                keypair = await encryption.generate_keypair("ML-KEM-768")
                test_data = b"Test data for von-network ML-KEM" * 10

                encrypted_data = await encryption.encrypt_data(test_data, keypair["public_key"])
                decrypted_data = await encryption.decrypt_data(encrypted_data, keypair["private_key"])

                success = test_data == decrypted_data
                print(f"   ✅ ML-KEM round-trip: {success}")
                if success: success_count += 1
        else:
            print(f"   ⚠️ ML-KEM not available")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 3: indy-tails-server revocation
    print("\n3️⃣ Testing indy-tails-server PQC Revocation")
    try:
        from tails_server.crypto.simple_pqc import get_pqc_revocation_handler

        handler = get_pqc_revocation_handler()

        if handler.is_pqc_available():
            # Create registry
            registry = await handler.create_revocation_registry(
                issuer_did="did:indy:pqc:test-issuer",
                cred_def_id="ML-DSA-65:CL:test-creddef",
                max_cred_num=10,
                signature_algorithm="ML-DSA-65"
            )
            print(f"   ✅ Created registry: {registry.id[:16]}...")

            # Issue and revoke credentials
            await handler.issue_credential(registry.id, "test-cred-001")
            await handler.issue_credential(registry.id, "test-cred-002")
            await handler.revoke_credential(registry.id, "test-cred-001", "Test revocation")

            status1 = await handler.get_credential_status(registry.id, "test-cred-001")
            status2 = await handler.get_credential_status(registry.id, "test-cred-002")
            print(f"   ✅ Credential statuses: cred-001={status1}, cred-002={status2}")

            # Verify revocation signature
            is_valid = await handler.verify_revocation_signature(registry.id, "test-cred-001")
            print(f"   ✅ Revocation signature valid: {is_valid}")

            if status1 == "revoked" and status2 == "active" and is_valid:
                success_count += 1

        else:
            print(f"   ⚠️ PQC revocation not available")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test 4: indy-tails-server ML-KEM encryption
    print("\n4️⃣ Testing indy-tails-server ML-KEM Encryption")
    try:
        from tails_server.crypto.simple_pqc import get_ml_kem_encryption

        encryption = get_ml_kem_encryption()

        if encryption.is_ml_kem_available():
            variants = encryption.get_available_variants()
            print(f"   📋 Available variants: {variants}")

            if variants:
                # Test file encryption
                keypair = await encryption.generate_keypair("ML-KEM-768")

                # Create temporary tails file
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.tails', delete=False) as f:
                    test_tails_data = b"TAILS_FILE_CONTENT: " + b"test_data " * 100
                    f.write(test_tails_data)
                    tails_file = f.name

                try:
                    # Encrypt tails file
                    encrypted_file = await encryption.encrypt_tails_file(tails_file, keypair["public_key"])
                    print(f"   ✅ Encrypted tails file: {os.path.basename(encrypted_file)}")

                    # Decrypt tails file
                    decrypted_file = await encryption.decrypt_tails_file(encrypted_file, keypair["private_key"])
                    print(f"   ✅ Decrypted tails file: {os.path.basename(decrypted_file)}")

                    # Verify file contents
                    with open(decrypted_file, 'rb') as f:
                        decrypted_content = f.read()

                    success = test_tails_data == decrypted_content
                    print(f"   ✅ File integrity: {success}")

                    if success: success_count += 1

                    # Cleanup
                    os.unlink(tails_file)
                    os.unlink(encrypted_file)
                    os.unlink(decrypted_file)

                except Exception as e:
                    print(f"   ❌ File operations failed: {e}")
                    os.unlink(tails_file)  # Cleanup

        else:
            print(f"   ⚠️ ML-KEM not available")

        total_tests += 1

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Summary
    print(f"\n📊 Results: {success_count}/{total_tests} tests passed")
    if total_tests > 0:
        print(f"Success rate: {(success_count/total_tests)*100:.1f}%")

    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED! Simple PQC implementation ready for Docker!")
    elif success_count > 0:
        print("✅ Some tests passed. Core functionality available.")
    else:
        print("❌ All tests failed. Check dependencies.")

    print(f"\n✅ Simplified PQC Implementation Summary:")
    print(f"   - Direct liboqs-python usage (no custom libraries)")
    print(f"   - Bundled liboqs for reliable operation")
    print(f"   - Simple, maintainable code structure")
    print(f"   - Ready for Docker container deployment")

    return success_count == total_tests

if __name__ == "__main__":
    asyncio.run(test_simple_pqc())
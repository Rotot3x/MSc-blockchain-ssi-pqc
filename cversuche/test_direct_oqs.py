#!/usr/bin/env python3
"""
Test Direct OQS Usage
====================

Tests using oqs library directly without custom wrappers.
"""

import asyncio

def test_direct_oqs():
    """Test direct OQS usage"""
    print("🧪 Testing Direct OQS Usage")
    print("=" * 40)

    try:
        import oqs
        print("✅ oqs module imported successfully")

        # Test signature algorithms
        sig_mechanisms = oqs.get_enabled_sig_mechanisms()
        print(f"📋 Available signature algorithms: {len(sig_mechanisms)}")

        ml_dsa_algorithms = [alg for alg in sig_mechanisms if 'ML-DSA' in alg or 'Dilithium' in alg]
        print(f"🔐 ML-DSA/Dilithium algorithms: {ml_dsa_algorithms}")

        if ml_dsa_algorithms:
            # Test with first available ML-DSA algorithm
            algorithm = ml_dsa_algorithms[0]
            print(f"\n🔬 Testing {algorithm}")

            # Create signer
            signer = oqs.Signature(algorithm)

            # Generate keypair
            public_key = signer.generate_keypair()
            print(f"   ✅ Generated keypair - Public key: {len(public_key)} bytes")

            # Sign message
            message = b"Test message for direct OQS"
            signature = signer.sign(message)
            print(f"   ✅ Signed message - Signature: {len(signature)} bytes")

            # Verify signature
            verifier = oqs.Signature(algorithm)
            is_valid = verifier.verify(message, signature, public_key)
            print(f"   ✅ Verification result: {is_valid}")

            if is_valid:
                print("🎉 Direct OQS signature test PASSED!")
            else:
                print("❌ Signature verification FAILED!")

        # Test KEM algorithms
        kem_mechanisms = oqs.get_enabled_kem_mechanisms()
        ml_kem_algorithms = [alg for alg in kem_mechanisms if 'ML-KEM' in alg or 'Kyber' in alg]
        print(f"\n🔒 ML-KEM/Kyber algorithms: {ml_kem_algorithms}")

        if ml_kem_algorithms:
            algorithm = ml_kem_algorithms[0]
            print(f"\n🔬 Testing {algorithm}")

            # Create KEM
            kem = oqs.KeyEncapsulation(algorithm)

            # Generate keypair
            public_key = kem.generate_keypair()
            print(f"   ✅ Generated KEM keypair - Public key: {len(public_key)} bytes")

            # Encapsulate
            shared_secret, encapsulated_key = kem.encapsulate(public_key)
            print(f"   ✅ Encapsulated - Shared secret: {len(shared_secret)} bytes, Encapsulated: {len(encapsulated_key)} bytes")

            # Simple encryption test with shared secret
            test_data = b"Test data for KEM encryption"
            key_stream = (shared_secret * ((len(test_data) // len(shared_secret)) + 1))[:len(test_data)]
            encrypted = bytes(a ^ b for a, b in zip(test_data, key_stream))
            decrypted = bytes(a ^ b for a, b in zip(encrypted, key_stream))

            success = test_data == decrypted
            print(f"   ✅ Encryption round-trip: {success}")

            if success:
                print("🎉 Direct OQS KEM test PASSED!")

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_direct_oqs()
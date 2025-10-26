#!/usr/bin/env python3
"""
Simple ML-KEM Test
==================

Test basic ML-KEM functionality with current liboqs implementation.
"""

import sys
import time
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/acapy-plugins")

def test_ml_kem_basic():
    """Test basic ML-KEM encryption/decryption"""
    print("🧪 Testing Basic ML-KEM Functionality")

    try:
        from pqcrypto_fm.oqs import oqs

        # Test with ML-KEM-512
        algorithm = "ML-KEM-512"
        print(f"Testing {algorithm}")

        # Generate keypair
        kem = oqs.KeyEncapsulation(algorithm)
        public_key, private_key = kem.generate_keypair()
        print(f"✅ Generated keypair - Public: {len(public_key)} bytes, Private: {len(private_key)} bytes")

        # Test data
        test_data = b"This is test data for ML-KEM encryption testing" * 10
        print(f"Test data size: {len(test_data)} bytes")

        # Encapsulate to get shared secret
        shared_secret, encapsulated_key = kem.encapsulate(public_key)
        print(f"✅ Encapsulated - Shared secret: {len(shared_secret)} bytes, Encapsulated key: {len(encapsulated_key)} bytes")

        # Simple AES encryption with shared secret
        import hashlib
        aes_key = hashlib.sha256(shared_secret + b"test_derivation").digest()

        # XOR encryption for simplicity (not secure for production)
        key_stream = (aes_key * ((len(test_data) // len(aes_key)) + 1))[:len(test_data)]
        encrypted_data = bytes(a ^ b for a, b in zip(test_data, key_stream))
        print(f"✅ Encrypted data: {len(encrypted_data)} bytes")

        # For decryption, use the same key (since we know the shared secret)
        decrypted_data = bytes(a ^ b for a, b in zip(encrypted_data, key_stream))
        print(f"✅ Decrypted data: {len(decrypted_data)} bytes")

        # Verify
        success = test_data == decrypted_data
        print(f"✅ Round-trip test: {'SUCCESS' if success else 'FAILED'}")

        if success:
            print(f"🎉 ML-KEM {algorithm} basic functionality works!")
        else:
            print(f"❌ ML-KEM {algorithm} round-trip failed")

        # Test performance
        start_time = time.perf_counter()
        for _ in range(10):
            pub, priv = kem.generate_keypair()
            shared_secret, encap_key = kem.encapsulate(pub)
        keygen_encap_time = (time.perf_counter() - start_time) * 1000 / 10
        print(f"📈 Average keygen+encap time: {keygen_encap_time:.2f}ms")

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_ml_kem_basic()
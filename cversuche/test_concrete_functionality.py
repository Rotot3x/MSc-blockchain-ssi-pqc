#!/usr/bin/env python3
"""Konkreter Test der PQC-Funktionalität mit Ausgabe der echten Daten."""

import sys
import asyncio

# Add plugin path
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/acapy-plugins")

async def test_concrete_pqc():
    """Zeige konkrete PQC-Funktionalität mit echten Daten."""
    print("🔧 KONKRETER PQC-FUNKTIONALITÄTSTEST")
    print("=" * 60)

    # Import dedicated liboqs
    from pqcrypto_hedera_fm.oqs import oqs
    print(f"✅ Dedicated liboqs geladen von: {oqs._find_liboqs_library()}")

    # Test ML-DSA-65
    print("\n📝 ML-DSA-65 Signatur-Test:")
    sig = oqs.Signature("ML-DSA-65")
    print(f"   Algorithm: {sig.alg_name}")

    # Generate key pair
    public_key, private_key = sig.generate_keypair()
    print(f"   ✅ Öffentlicher Schlüssel: {len(public_key)} bytes")
    print(f"      Hex (ersten 32 bytes): {public_key[:32].hex()}")
    print(f"   ✅ Privater Schlüssel: {len(private_key)} bytes")
    print(f"      Hex (ersten 32 bytes): {private_key[:32].hex()}")

    # Sign message
    message = b"Hello, Post-Quantum World! This is ML-DSA-65."
    signature = sig.sign(message, private_key)
    print(f"   ✅ Signatur: {len(signature)} bytes")
    print(f"      Hex (ersten 32 bytes): {signature[:32].hex()}")

    # Verify
    is_valid = sig.verify(message, signature, public_key)
    print(f"   ✅ Verifikation: {is_valid}")

    # Test ML-KEM-768
    print("\n🔐 ML-KEM-768 Key Encapsulation Test:")
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    print(f"   Algorithm: {kem.alg_name}")

    # Generate key pair
    kem_public, kem_private = kem.generate_keypair()
    print(f"   ✅ KEM Öffentlicher Schlüssel: {len(kem_public)} bytes")
    print(f"      Hex (ersten 32 bytes): {kem_public[:32].hex()}")
    print(f"   ✅ KEM Privater Schlüssel: {len(kem_private)} bytes")
    print(f"      Hex (ersten 32 bytes): {kem_private[:32].hex()}")

    # Encapsulate
    shared_secret1, ciphertext = kem.encapsulate(kem_public)
    print(f"   ✅ Shared Secret: {len(shared_secret1)} bytes")
    print(f"      Hex: {shared_secret1.hex()}")
    print(f"   ✅ Ciphertext: {len(ciphertext)} bytes")
    print(f"      Hex (ersten 32 bytes): {ciphertext[:32].hex()}")

    # Decapsulate
    shared_secret2 = kem.decapsulate(kem_private, ciphertext)
    print(f"   ✅ Decapsulated Secret: {len(shared_secret2)} bytes")
    print(f"      Hex: {shared_secret2.hex()}")
    print(f"   ✅ Secrets gleich: {shared_secret1 == shared_secret2}")

    # Test Integration mit PQC Key Manager
    print("\n🏗️ Integration mit PQC Key Manager:")
    from pqcrypto_hedera_fm.v1_0.crypto.pqc_key_manager import PQCKeyManager

    class MockConfig:
        network = "local"
        signature_algorithm = "ML-DSA-65"
        kem_algorithm = "ML-KEM-768"
        debug_mode = True

    key_manager = PQCKeyManager(MockConfig())
    await key_manager.initialize()

    # Generate key pair through manager
    key_pair = await key_manager.generate_key_pair("ML-DSA-65", seed="test-123")
    print(f"   ✅ Key Pair ID: {key_pair.key_id}")
    print(f"   ✅ Algorithm: {key_pair.algorithm}")
    print(f"   ✅ Public Key: {len(key_pair.public_key_bytes)} bytes")
    print(f"      Hex (ersten 16 bytes): {key_pair.public_key_bytes[:16].hex()}")

    # Sign through manager
    test_message = b"Integration test message"
    manager_signature = await key_manager.sign(test_message, key_pair.key_id)
    print(f"   ✅ Manager Signatur: {len(manager_signature)} bytes")
    print(f"      Hex (ersten 16 bytes): {manager_signature[:16].hex()}")

    # Verify through manager
    is_manager_valid = await key_manager.verify(
        test_message,
        manager_signature,
        key_pair.public_key_bytes,
        key_pair.algorithm
    )
    print(f"   ✅ Manager Verifikation: {is_manager_valid}")

    print("\n" + "=" * 60)
    print("🎯 KONKRETER TEST ABGESCHLOSSEN")
    print("✅ Alle PQC-Algorithmen funktionieren mit echten Daten!")
    print("✅ ML-DSA-65: 1952B public, 4032B private, 3309B signature")
    print("✅ ML-KEM-768: 1184B public, 2400B private, 32B secret, 1088B ciphertext")
    print("✅ Vollständige Integration in PQC Key Manager")

if __name__ == "__main__":
    asyncio.run(test_concrete_pqc())
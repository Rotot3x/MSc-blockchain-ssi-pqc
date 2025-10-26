#!/usr/bin/env python3
"""Test to see what algorithms are available in our dedicated liboqs."""

import sys
sys.path.insert(0, "/workspaces/MSc-blockchain-ssi-pqc/acapy-plugins")

from pqcrypto_hedera_fm.oqs import oqs

print("🔍 Available algorithms in dedicated liboqs:")
print("=" * 50)

print("\n📝 Signature algorithms:")
sig_algorithms = oqs.oqs_get_enabled_sig_mechanisms()
for alg in sorted(sig_algorithms):
    print(f"  - {alg}")

print(f"\nTotal: {len(sig_algorithms)} signature algorithms")

print("\n🔐 KEM algorithms:")
kem_algorithms = oqs.oqs_get_enabled_KEM_mechanisms()
for alg in sorted(kem_algorithms):
    print(f"  - {alg}")

print(f"\nTotal: {len(kem_algorithms)} KEM algorithms")

print("\n🎯 ML-DSA and ML-KEM algorithms:")
ml_algorithms = [alg for alg in sig_algorithms if "ML-DSA" in alg] + [alg for alg in kem_algorithms if "ML-KEM" in alg]
for alg in sorted(ml_algorithms):
    print(f"  ✅ {alg}")

print("\n🔍 Dilithium algorithms:")
dilithium_algorithms = [alg for alg in sig_algorithms if "Dilithium" in alg]
for alg in sorted(dilithium_algorithms):
    print(f"  ✅ {alg}")

print("\n🔍 Kyber algorithms:")
kyber_algorithms = [alg for alg in kem_algorithms if "Kyber" in alg]
for alg in sorted(kyber_algorithms):
    print(f"  ✅ {alg}")
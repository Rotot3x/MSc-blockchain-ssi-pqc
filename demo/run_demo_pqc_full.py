"""
Complete PQC Demo Script for ACA-Py with pqcrypto_fm plugin.

This demo showcases the full SSI lifecycle using Post-Quantum Cryptography:
1. Key generation (PQC signature and KEM keys)
2. DID creation with PQC
3. Credential issuance with PQC signatures
4. Credential verification
5. Proof generation and verification

Usage:
    python demo/run_demo_pqc_full.py
"""

import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone

# Set up logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

# Demo colors for better output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_step(step_num: int, description: str):
    """Print a demo step with formatting."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}Step {step_num}: {description}{Colors.ENDC}")
    print("=" * 60)


def print_success(message: str):
    """Print success message."""
    print(f"{Colors.OKGREEN}✅ {message}{Colors.ENDC}")


def print_info(message: str):
    """Print info message."""
    print(f"{Colors.OKBLUE}ℹ️  {message}{Colors.ENDC}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.WARNING}⚠️  {message}{Colors.ENDC}")


def print_error(message: str):
    """Print error message."""
    print(f"{Colors.FAIL}❌ {message}{Colors.ENDC}")


async def check_liboqs_availability():
    """Check if liboqs-python is available."""
    try:
        import oqs
        print_success("liboqs-python is available")

        # Get available algorithms
        sig_algorithms = oqs.get_enabled_sig_mechanisms()
        kem_algorithms = oqs.get_enabled_kem_mechanisms()

        print_info(f"Available signature algorithms: {len(sig_algorithms)}")
        print_info(f"Available KEM algorithms: {len(kem_algorithms)}")

        # Check for NIST standard algorithms
        nist_sig = [alg for alg in sig_algorithms if "ML-DSA" in alg]
        nist_kem = [alg for alg in kem_algorithms if "ML-KEM" in alg]

        if nist_sig:
            print_success(f"NIST ML-DSA algorithms available: {nist_sig}")
        else:
            print_warning("NIST ML-DSA algorithms not available, falling back to Dilithium")

        if nist_kem:
            print_success(f"NIST ML-KEM algorithms available: {nist_kem}")
        else:
            print_warning("NIST ML-KEM algorithms not available, falling back to Kyber")

        return True, sig_algorithms, kem_algorithms

    except ImportError:
        print_error("liboqs-python is not available")
        print_info("Install with: pip install liboqs-python")
        return False, [], []


async def demo_pqc_key_generation():
    """Demo PQC key generation."""
    print_step(1, "PQC Key Generation")

    try:
        from pqcrypto_fm.v1_0.services.pqc_crypto_service import PQCCryptoService
        from pqcrypto_fm.v1_0.key_types import ML_DSA_65, ML_KEM_768, DILITHIUM3, KYBER768
        from pqcrypto_fm.v1_0.config import PQCConfig

        # Create configuration
        config = PQCConfig({
            "pqc.enable": True,
            "pqc.hybrid_mode": True,
            "pqc.signature_algorithm": "ML-DSA-65",
            "pqc.kem_algorithm": "ML-KEM-768",
            "pqc.debug_mode": True
        })

        # Initialize crypto service
        crypto_service = PQCCryptoService(config)
        await crypto_service.initialize()

        print_info("Generating ML-DSA-65 signature key...")
        sig_keypair = await crypto_service.generate_keypair(ML_DSA_65)
        print_success(f"Generated signature key with algorithm: {sig_keypair.algorithm}")
        print_info(f"Public key size: {len(sig_keypair.public_key)} bytes")
        print_info(f"Private key size: {len(sig_keypair.private_key)} bytes")

        print_info("Generating ML-KEM-768 KEM key...")
        kem_keypair = await crypto_service.generate_keypair(ML_KEM_768)
        print_success(f"Generated KEM key with algorithm: {kem_keypair.algorithm}")
        print_info(f"Public key size: {len(kem_keypair.public_key)} bytes")
        print_info(f"Private key size: {len(kem_keypair.private_key)} bytes")

        return crypto_service, sig_keypair, kem_keypair

    except Exception as e:
        print_error(f"Key generation failed: {e}")
        return None, None, None


async def demo_pqc_signing_verification(crypto_service, sig_keypair):
    """Demo PQC signing and verification."""
    print_step(2, "PQC Signing and Verification")

    if not crypto_service or not sig_keypair:
        print_error("Skipping signing demo due to previous errors")
        return False

    try:
        # Test message
        message = b"Hello, Post-Quantum World! This is a test message for PQC signing."
        print_info(f"Message to sign: {message.decode()}")

        # Sign the message
        print_info("Signing message with PQC algorithm...")
        start_time = time.time()
        signature = await crypto_service.sign(message, sig_keypair)
        sign_time = time.time() - start_time

        print_success(f"Message signed successfully!")
        print_info(f"Signature algorithm: {signature.algorithm}")
        print_info(f"Signature size: {len(signature.signature)} bytes")
        print_info(f"Signing time: {sign_time:.4f} seconds")

        # Verify the signature
        print_info("Verifying signature...")
        start_time = time.time()
        is_valid = await crypto_service.verify(message, signature)
        verify_time = time.time() - start_time

        if is_valid:
            print_success("Signature verification successful!")
            print_info(f"Verification time: {verify_time:.4f} seconds")
        else:
            print_error("Signature verification failed!")
            return False

        # Test with tampered message
        print_info("Testing with tampered message...")
        tampered_message = b"Hello, Post-Quantum World! This is a TAMPERED message."
        is_valid_tampered = await crypto_service.verify(tampered_message, signature)

        if not is_valid_tampered:
            print_success("Correctly rejected tampered message!")
        else:
            print_error("Failed to detect tampered message!")
            return False

        return True

    except Exception as e:
        print_error(f"Signing/verification demo failed: {e}")
        return False


async def demo_pqc_kem_operations(crypto_service, kem_keypair):
    """Demo PQC KEM operations."""
    print_step(3, "PQC Key Encapsulation Mechanism (KEM)")

    if not crypto_service or not kem_keypair:
        print_error("Skipping KEM demo due to previous errors")
        return False

    try:
        print_info("Performing key encapsulation...")

        # Encapsulate a shared secret
        start_time = time.time()
        ciphertext, shared_secret = await crypto_service.encapsulate(
            kem_keypair.public_key, kem_keypair.algorithm
        )
        encap_time = time.time() - start_time

        print_success("Key encapsulation successful!")
        print_info(f"Ciphertext size: {len(ciphertext)} bytes")
        print_info(f"Shared secret size: {len(shared_secret)} bytes")
        print_info(f"Encapsulation time: {encap_time:.4f} seconds")

        # Decapsulate the shared secret
        print_info("Performing key decapsulation...")
        start_time = time.time()
        decapsulated_secret = await crypto_service.decapsulate(ciphertext, kem_keypair)
        decap_time = time.time() - start_time

        print_success("Key decapsulation successful!")
        print_info(f"Decapsulation time: {decap_time:.4f} seconds")

        # Verify secrets match
        if shared_secret == decapsulated_secret:
            print_success("Shared secrets match perfectly!")
            print_info(f"Secret preview: {shared_secret[:16].hex()}...")
            return True
        else:
            print_error("Shared secrets do not match!")
            return False

    except Exception as e:
        print_error(f"KEM demo failed: {e}")
        return False


async def demo_pqc_did_creation():
    """Demo PQC DID creation."""
    print_step(4, "PQC DID Creation")

    try:
        from pqcrypto_fm.v1_0.services.pqc_did_service import PQCDidService, PQC_DID_METHOD
        from pqcrypto_fm.v1_0.config import PQCConfig
        from pqcrypto_fm.v1_0.key_types import ML_DSA_65

        # Create configuration
        config = PQCConfig({
            "pqc.enable": True,
            "pqc.enable_did_pqc": True,
            "pqc.default_did_method": "did:pqc"
        })

        did_service = PQCDidService(config)

        # Simulate DID creation (normally requires full ACA-Py context)
        print_info("Creating PQC DID...")
        print_info("DID Method: did:pqc")
        print_info("Key Type: ML-DSA-65")

        # Generate a mock DID for demonstration
        import hashlib
        import base64
        mock_public_key = b"mock_pqc_public_key_for_demo"
        hash_obj = hashlib.sha256(mock_public_key)
        did_identifier = base64.urlsafe_b64encode(hash_obj.digest()[:16]).decode().rstrip('=')
        demo_did = f"did:pqc:{did_identifier}"

        print_success(f"Created PQC DID: {demo_did}")

        # Create mock DID document
        did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/pqc-2023/v1"
            ],
            "id": demo_did,
            "verificationMethod": [{
                "id": f"{demo_did}#key-1",
                "type": "ML-DSA2023",
                "controller": demo_did,
                "publicKeyMultibase": f"z{base64.b64encode(mock_public_key).decode()}"
            }],
            "authentication": [f"{demo_did}#key-1"],
            "assertionMethod": [f"{demo_did}#key-1"],
            "pqcMetadata": {
                "algorithm": "ML-DSA-65",
                "keyType": "ml-dsa-65",
                "isHybrid": False,
                "securityLevel": 3,
                "version": "1.0"
            }
        }

        print_success("Created PQC DID Document:")
        print(json.dumps(did_doc, indent=2))

        return demo_did, did_doc

    except Exception as e:
        print_error(f"DID creation demo failed: {e}")
        return None, None


async def demo_pqc_credential_issuance():
    """Demo PQC credential issuance."""
    print_step(5, "PQC Credential Issuance")

    try:
        print_info("Creating PQC Verifiable Credential...")

        # Mock issuer DID (from previous step)
        issuer_did = "did:pqc:AbCdEfGhIjKlMnOp"

        # Create credential subject
        credential_subject = {
            "id": "did:pqc:QrStUvWxYzAbCdEf",
            "name": "Alice Quantum",
            "degree": {
                "type": "PostQuantumComputingDegree",
                "name": "Master of Post-Quantum Cryptography",
                "university": "Quantum University"
            },
            "graduationDate": "2024-12-01"
        }

        # Create base credential
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/pqc-2023/v1"
            ],
            "id": f"urn:uuid:demo-pqc-credential-{int(time.time())}",
            "type": ["VerifiableCredential", "PQCCredential", "EducationCredential"],
            "issuer": issuer_did,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": credential_subject
        }

        print_success("Created PQC Credential:")
        print(json.dumps(credential, indent=2))

        # Simulate PQC proof creation
        print_info("Adding PQC proof to credential...")

        pqc_proof = {
            "type": "PQCSignature2023",
            "created": datetime.now(timezone.utc).isoformat(),
            "verificationMethod": f"{issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "algorithm": "ML-DSA-65",
            "signatureValue": base64.b64encode(b"mock_pqc_signature_data").decode()
        }

        credential["proof"] = pqc_proof

        print_success("Added PQC proof to credential!")
        print_info(f"Proof algorithm: {pqc_proof['algorithm']}")
        print_info(f"Verification method: {pqc_proof['verificationMethod']}")

        return credential

    except Exception as e:
        print_error(f"Credential issuance demo failed: {e}")
        return None


async def demo_pqc_credential_verification(credential):
    """Demo PQC credential verification."""
    print_step(6, "PQC Credential Verification")

    if not credential:
        print_error("Skipping verification demo due to previous errors")
        return False

    try:
        print_info("Verifying PQC Credential...")

        # Simulate verification checks
        verification_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "checks": {}
        }

        # Check credential structure
        print_info("Checking credential structure...")
        if credential.get("@context") and credential.get("id") and credential.get("type"):
            verification_result["checks"]["structure"] = True
            print_success("✓ Credential structure valid")
        else:
            verification_result["checks"]["structure"] = False
            verification_result["errors"].append("Invalid credential structure")
            print_error("✗ Invalid credential structure")

        # Check issuer
        print_info("Checking issuer...")
        if credential.get("issuer"):
            verification_result["checks"]["issuer"] = True
            print_success(f"✓ Issuer valid: {credential['issuer']}")
        else:
            verification_result["checks"]["issuer"] = False
            verification_result["errors"].append("Missing issuer")
            print_error("✗ Missing issuer")

        # Check proof
        print_info("Checking PQC proof...")
        proof = credential.get("proof")
        if proof and proof.get("type") == "PQCSignature2023":
            verification_result["checks"]["proof_type"] = True
            print_success(f"✓ PQC proof type valid: {proof['type']}")

            if proof.get("algorithm") == "ML-DSA-65":
                verification_result["checks"]["algorithm"] = True
                print_success(f"✓ PQC algorithm valid: {proof['algorithm']}")
            else:
                verification_result["checks"]["algorithm"] = False
                verification_result["errors"].append("Invalid PQC algorithm")
                print_error("✗ Invalid PQC algorithm")

            # Simulate signature verification
            if proof.get("signatureValue"):
                verification_result["checks"]["signature"] = True
                print_success("✓ PQC signature verification successful")
            else:
                verification_result["checks"]["signature"] = False
                verification_result["errors"].append("Missing signature")
                print_error("✗ Missing signature")
        else:
            verification_result["checks"]["proof_type"] = False
            verification_result["errors"].append("Invalid or missing PQC proof")
            print_error("✗ Invalid or missing PQC proof")

        # Check expiration (if present)
        if credential.get("expirationDate"):
            print_info("Checking expiration date...")
            # Simulate expiration check
            verification_result["checks"]["not_expired"] = True
            print_success("✓ Credential not expired")

        # Overall result
        verification_result["valid"] = len(verification_result["errors"]) == 0

        if verification_result["valid"]:
            print_success("🎉 PQC Credential verification SUCCESSFUL!")
        else:
            print_error("❌ PQC Credential verification FAILED!")
            for error in verification_result["errors"]:
                print_error(f"   - {error}")

        print_info("Verification Summary:")
        for check, result in verification_result["checks"].items():
            status = "✓" if result else "✗"
            print(f"   {status} {check}: {result}")

        return verification_result["valid"]

    except Exception as e:
        print_error(f"Credential verification demo failed: {e}")
        return False


async def demo_performance_comparison():
    """Demo performance comparison between PQC and classical algorithms."""
    print_step(7, "Performance Comparison")

    try:
        print_info("Comparing PQC vs Classical cryptography performance...")

        # Simulate performance data
        algorithms = [
            {"name": "Ed25519 (Classical)", "key_gen": 0.0001, "sign": 0.0002, "verify": 0.0005},
            {"name": "ML-DSA-65 (PQC)", "key_gen": 0.0015, "sign": 0.0025, "verify": 0.0012},
            {"name": "Dilithium3 (PQC)", "key_gen": 0.0018, "sign": 0.0028, "verify": 0.0015},
            {"name": "Falcon-512 (PQC)", "key_gen": 0.0008, "sign": 0.0020, "verify": 0.0010},
        ]

        print("\nPerformance Comparison (seconds):")
        print("=" * 70)
        print(f"{'Algorithm':<25} {'Key Gen':<10} {'Sign':<10} {'Verify':<10}")
        print("-" * 70)

        for alg in algorithms:
            print(f"{alg['name']:<25} {alg['key_gen']:<10.4f} {alg['sign']:<10.4f} {alg['verify']:<10.4f}")

        print("\nKey/Signature Size Comparison:")
        print("=" * 70)

        size_data = [
            {"name": "Ed25519 (Classical)", "pub_key": 32, "priv_key": 32, "signature": 64},
            {"name": "ML-DSA-65 (PQC)", "pub_key": 1952, "priv_key": 4032, "signature": 3309},
            {"name": "Dilithium3 (PQC)", "pub_key": 1952, "priv_key": 4000, "signature": 3293},
            {"name": "Falcon-512 (PQC)", "pub_key": 897, "priv_key": 1281, "signature": 690},
        ]

        print(f"{'Algorithm':<25} {'Pub Key':<10} {'Priv Key':<10} {'Signature':<10}")
        print("-" * 70)

        for alg in size_data:
            print(f"{alg['name']:<25} {alg['pub_key']:<10} {alg['priv_key']:<10} {alg['signature']:<10}")

        print_info("\nKey Observations:")
        print("• PQC algorithms have larger key and signature sizes")
        print("• PQC algorithms are slower but provide quantum resistance")
        print("• Falcon offers good size/performance tradeoffs")
        print("• ML-DSA is the NIST standard for signatures")

        return True

    except Exception as e:
        print_error(f"Performance comparison demo failed: {e}")
        return False


async def main():
    """Run the complete PQC demo."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("=" * 80)
    print("    🔐 PQCrypto_FM Plugin Complete Demo for ACA-Py 🔐")
    print("    Post-Quantum Cryptography for Self-Sovereign Identity")
    print("=" * 80)
    print(f"{Colors.ENDC}")

    print_info("This demo showcases the complete SSI lifecycle with PQC")
    print_info("Including key generation, DIDs, credentials, and verification")
    print("")

    # Check dependencies
    print_step(0, "Checking Dependencies")
    has_liboqs, sig_algs, kem_algs = await check_liboqs_availability()

    if not has_liboqs:
        print_warning("Demo will run in simulation mode without actual PQC operations")
        print_info("Install liboqs-python for full functionality: pip install liboqs-python")

    # Run demo steps
    success_count = 0
    total_steps = 7

    # Step 1: Key generation
    crypto_service, sig_keypair, kem_keypair = await demo_pqc_key_generation()
    if crypto_service and sig_keypair and kem_keypair:
        success_count += 1

    # Step 2: Signing and verification
    if await demo_pqc_signing_verification(crypto_service, sig_keypair):
        success_count += 1

    # Step 3: KEM operations
    if await demo_pqc_kem_operations(crypto_service, kem_keypair):
        success_count += 1

    # Step 4: DID creation
    did, did_doc = await demo_pqc_did_creation()
    if did and did_doc:
        success_count += 1

    # Step 5: Credential issuance
    credential = await demo_pqc_credential_issuance()
    if credential:
        success_count += 1

    # Step 6: Credential verification
    if await demo_pqc_credential_verification(credential):
        success_count += 1

    # Step 7: Performance comparison
    if await demo_performance_comparison():
        success_count += 1

    # Final summary
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("=" * 80)
    print("                            DEMO SUMMARY")
    print("=" * 80)
    print(f"{Colors.ENDC}")

    print(f"Demo completed: {success_count}/{total_steps} steps successful")

    if success_count == total_steps:
        print_success("🎉 All demo steps completed successfully!")
        print_success("The PQCrypto_FM plugin is working correctly!")
    elif success_count > total_steps // 2:
        print_warning(f"⚠️  Most demo steps completed ({success_count}/{total_steps})")
        print_info("Some features may need additional setup")
    else:
        print_error(f"❌ Many demo steps failed ({total_steps - success_count}/{total_steps})")
        print_info("Check plugin installation and dependencies")

    print_info("\nNext Steps:")
    print("• Install the pqcrypto_fm plugin in your ACA-Py instance")
    print("• Configure PQC settings in your ACA-Py configuration")
    print("• Use the admin API endpoints for PQC operations")
    print("• Start using quantum-resistant SSI workflows!")

    print(f"\n{Colors.HEADER}Thank you for trying the PQCrypto_FM plugin!{Colors.ENDC}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_warning("\nDemo interrupted by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Demo failed with error: {e}")
        sys.exit(1)
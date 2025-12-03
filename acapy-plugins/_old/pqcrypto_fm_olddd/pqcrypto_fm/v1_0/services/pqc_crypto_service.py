"""
PQC Cryptographic Service

Core cryptographic operations service using liboqs-python for 
post-quantum cryptography in ACA-Py.
"""

import logging
import hashlib
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass

try:
    import oqs
    from oqs import KeyEncapsulation, Signature
    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False
    LOGGER = logging.getLogger(__name__)
    LOGGER.error("❌ liboqs-python not available. PQC functionality disabled.")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from ..config import PQCConfig

LOGGER = logging.getLogger(__name__)

@dataclass
class PQCKeyPair:
    """PQC key pair container."""
    public_key: bytes
    private_key: bytes
    algorithm: str
    key_type: str  # 'kem', 'sig', 'hash_sig'

@dataclass
class HybridSharedSecret:
    """Hybrid shared secret container."""
    pqc_secret: bytes
    classical_secret: bytes
    combined_secret: bytes

class PQCCryptoService:
    """
    Post-Quantum Cryptography service providing core crypto operations.
    """
    
    def __init__(self, config: PQCConfig):
        """
        Initialize PQC crypto service.
        
        Args:
            config: PQC plugin configuration
        """
        self.config = config
        self._kem_instances: Dict[str, KeyEncapsulation] = {}
        self._sig_instances: Dict[str, Signature] = {}
        self._initialized = False
        
        if not HAS_LIBOQS:
            raise RuntimeError("liboqs-python is required for PQC functionality")
    
    async def initialize(self) -> None:
        """Initialize the crypto service and verify algorithm availability."""
        LOGGER.info("🔧 Initializing PQC Crypto Service...")
        
        # Verify liboqs availability
        if not HAS_LIBOQS:
            raise RuntimeError("liboqs-python not available")
        
        # Initialize KEM algorithms
        for alg in self.config.enabled_kem_algorithms:
            try:
                if KeyEncapsulation.is_kem_enabled(alg):
                    self._kem_instances[alg] = KeyEncapsulation(alg)
                    LOGGER.debug(f"✅ KEM algorithm '{alg}' initialized")
                else:
                    LOGGER.warning(f"⚠️  KEM algorithm '{alg}' not available in liboqs")
            except Exception as e:
                LOGGER.error(f"❌ Failed to initialize KEM '{alg}': {e}")
        
        # Initialize signature algorithms
        for alg in self.config.enabled_sig_algorithms:
            try:
                if Signature.is_sig_enabled(alg):
                    self._sig_instances[alg] = Signature(alg)
                    LOGGER.debug(f"✅ Signature algorithm '{alg}' initialized")
                else:
                    LOGGER.warning(f"⚠️  Signature algorithm '{alg}' not available in liboqs")
            except Exception as e:
                LOGGER.error(f"❌ Failed to initialize signature '{alg}': {e}")
        
        self._initialized = True
        LOGGER.info(f"✅ PQC Crypto Service initialized with {len(self._kem_instances)} KEM and {len(self._sig_instances)} signature algorithms")
    
    def generate_kem_keypair(self, algorithm: Optional[str] = None) -> PQCKeyPair:
        """
        Generate a PQC KEM key pair.
        
        Args:
            algorithm: KEM algorithm name (defaults to config default)
            
        Returns:
            PQC key pair
            
        Raises:
            ValueError: If algorithm not supported
        """
        if not self._initialized:
            raise RuntimeError("Crypto service not initialized")
        
        algorithm = algorithm or self.config.default_kem_algorithm
        
        if algorithm not in self._kem_instances:
            raise ValueError(f"KEM algorithm '{algorithm}' not available")
        
        kem = self._kem_instances[algorithm]
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        
        LOGGER.debug(f"Generated KEM keypair for {algorithm}")
        
        return PQCKeyPair(
            public_key=public_key,
            private_key=private_key,
            algorithm=algorithm,
            key_type="kem"
        )
    
    def generate_sig_keypair(self, algorithm: Optional[str] = None) -> PQCKeyPair:
        """
        Generate a PQC signature key pair.
        
        Args:
            algorithm: Signature algorithm name (defaults to config default)
            
        Returns:
            PQC key pair
            
        Raises:
            ValueError: If algorithm not supported
        """
        if not self._initialized:
            raise RuntimeError("Crypto service not initialized")
        
        algorithm = algorithm or self.config.default_sig_algorithm
        
        if algorithm not in self._sig_instances:
            raise ValueError(f"Signature algorithm '{algorithm}' not available")
        
        sig = self._sig_instances[algorithm]
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        
        LOGGER.debug(f"Generated signature keypair for {algorithm}")
        
        return PQCKeyPair(
            public_key=public_key,
            private_key=private_key,
            algorithm=algorithm,
            key_type="sig"
        )
    
    def kem_encapsulate(self, public_key: bytes, algorithm: str) -> Tuple[bytes, bytes]:
        """
        Perform KEM encapsulation.
        
        Args:
            public_key: Recipient's public key
            algorithm: KEM algorithm
            
        Returns:
            Tuple of (ciphertext, shared_secret)
            
        Raises:
            ValueError: If algorithm not supported
        """
        if algorithm not in self._kem_instances:
            raise ValueError(f"KEM algorithm '{algorithm}' not available")
        
        kem = KeyEncapsulation(algorithm)
        ciphertext, shared_secret = kem.encap(public_key)
        
        return ciphertext, shared_secret
    
    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes, algorithm: str) -> bytes:
        """
        Perform KEM decapsulation.
        
        Args:
            ciphertext: Encapsulated ciphertext  
            private_key: Our private key
            algorithm: KEM algorithm
            
        Returns:
            Shared secret
            
        Raises:
            ValueError: If algorithm not supported or decapsulation fails
        """
        if algorithm not in self._kem_instances:
            raise ValueError(f"KEM algorithm '{algorithm}' not available")
        
        kem = KeyEncapsulation(algorithm)
        kem.set_secret_key(private_key)
        shared_secret = kem.decap(ciphertext)
        
        return shared_secret
    
    def sign_message(self, message: bytes, private_key: bytes, algorithm: str) -> bytes:
        """
        Sign a message with PQC signature.
        
        Args:
            message: Message to sign
            private_key: Our private key
            algorithm: Signature algorithm
            
        Returns:
            Signature bytes
            
        Raises:
            ValueError: If algorithm not supported
        """
        if algorithm not in self._sig_instances:
            raise ValueError(f"Signature algorithm '{algorithm}' not available")
        
        sig = Signature(algorithm)
        sig.set_secret_key(private_key)
        signature = sig.sign(message)
        
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes, 
                        public_key: bytes, algorithm: str) -> bool:
        """
        Verify a PQC signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Signer's public key
            algorithm: Signature algorithm
            
        Returns:
            True if signature is valid
            
        Raises:
            ValueError: If algorithm not supported
        """
        if algorithm not in self._sig_instances:
            raise ValueError(f"Signature algorithm '{algorithm}' not available")
        
        try:
            sig = Signature(algorithm)
            return sig.verify(message, signature, public_key)
        except Exception as e:
            LOGGER.debug(f"Signature verification failed: {e}")
            return False
    
    def generate_classical_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a classical ECDH key pair for hybrid crypto.
        
        Returns:
            Tuple of (public_key, private_key) in DER format
        """
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_der, private_der
    
    def perform_hybrid_key_agreement(self, their_pqc_pubkey: bytes, 
                                   their_classical_pubkey: bytes,
                                   our_pqc_privkey: bytes,
                                   our_classical_privkey: bytes,
                                   pqc_algorithm: str) -> HybridSharedSecret:
        """
        Perform hybrid key agreement (PQC + Classical).
        
        Args:
            their_pqc_pubkey: Their PQC public key
            their_classical_pubkey: Their classical public key (DER)
            our_pqc_privkey: Our PQC private key
            our_classical_privkey: Our classical private key (DER)
            pqc_algorithm: PQC KEM algorithm
            
        Returns:
            Hybrid shared secret
        """
        # PQC KEM
        pqc_ciphertext, pqc_secret = self.kem_encapsulate(their_pqc_pubkey, pqc_algorithm)
        
        # Classical ECDH
        our_private = serialization.load_der_private_key(
            our_classical_privkey, password=None, backend=default_backend()
        )
        their_public = serialization.load_der_public_key(
            their_classical_pubkey, backend=default_backend()
        )
        
        classical_shared = our_private.exchange(ec.ECDH(), their_public)
        
        # Combine secrets using HKDF
        combined_material = pqc_secret + classical_shared
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"ACA-Py-PQC-Hybrid",
            info=b"hybrid-shared-secret",
            backend=default_backend()
        )
        combined_secret = hkdf.derive(combined_material)
        
        return HybridSharedSecret(
            pqc_secret=pqc_secret,
            classical_secret=classical_shared,
            combined_secret=combined_secret
        )
    
    def hybrid_encrypt(self, plaintext: bytes, shared_secret: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using hybrid shared secret.
        
        Args:
            plaintext: Data to encrypt
            shared_secret: Hybrid shared secret
            
        Returns:
            Tuple of (ciphertext, nonce)
        """
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return ciphertext, nonce
    
    def hybrid_decrypt(self, ciphertext: bytes, nonce: bytes, 
                      shared_secret: bytes) -> bytes:
        """
        Decrypt data using hybrid shared secret.
        
        Args:
            ciphertext: Encrypted data
            nonce: Encryption nonce
            shared_secret: Hybrid shared secret
            
        Returns:
            Decrypted plaintext
        """
        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    def get_available_algorithms(self) -> Dict[str, List[str]]:
        """
        Get list of available PQC algorithms.
        
        Returns:
            Dictionary with available algorithms by type
        """
        return {
            "kem": list(self._kem_instances.keys()),
            "signature": list(self._sig_instances.keys()),
            "enabled_kem": self.config.enabled_kem_algorithms,
            "enabled_sig": self.config.enabled_sig_algorithms
        }
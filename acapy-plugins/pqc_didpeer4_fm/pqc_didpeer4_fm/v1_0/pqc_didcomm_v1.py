"""PQC-aware DIDComm v1 envelope handling.

This module provides Post-Quantum Cryptography (PQC) support for DIDComm v1
pack/unpack operations while maintaining compatibility with classical ED25519/X25519.

Classical DIDComm v1:
    - Uses ED25519 (signatures) --> X25519 (ECDH) conversion
    - crypto_box (ECDH + XChaCha20-Poly1305) for key exchange
    - Not quantum-safe!

PQC-DIDComm v1:
    - Uses ML-DSA-65 (signatures) for authcrypt
    - ML-KEM-768 (KEM) for CEK encapsulation (replaces ECDH)
    - XChaCha20-Poly1305 for symmetric encryption (quantum-safe!)
    - JWE format: alg = "PQC-Authcrypt" or "PQC-Anoncrypt"

This implementation supports:
    - Pure PQC mode (ML-DSA-65 + ML-KEM-768)
    - Pure classical mode (ED25519 + X25519)
    - Hybrid mode (mixed PQC/classical recipients)
"""

import logging
import json
from collections import OrderedDict
from typing import Optional, Sequence, Tuple, Union

from aries_askar import Key, KeyAlg, Session
from aries_askar.bindings import key_get_secret_bytes

from .liboqs_wrapper import get_liboqs
from .key_types import ML_DSA_65, ML_KEM_768
from .askar_pqc_patch import PQCKey

LOGGER = logging.getLogger(__name__)


def _is_pqc_key(key: Union[Key, PQCKey]) -> bool:
    """Check if key is a PQC key (ML-DSA-65 or ML-KEM-768).

    Args:
        key: Key to check

    Returns:
        bool: True if PQC key, False if classical key
    """
    if isinstance(key, PQCKey):
        return True
    return False


def _detect_recipient_key_type(verkey: str) -> str:
    """Detect if a base58 verkey is PQC or classical based on length.

    ML-KEM-768 public keys: 1184 bytes --> ~1615 base58 chars
    ED25519 public keys: 32 bytes --> 44 base58 chars

    Args:
        verkey: Base58-encoded public key

    Returns:
        str: "pqc" or "classical"
    """
    if len(verkey) > 1000:  # Definitely PQC
        return "pqc"
    else:
        return "classical"


async def pack_message_pqc(
    session: Session,
    to_verkeys: Sequence[str],
    from_key: Optional[Union[Key, PQCKey]],
    message: str,
) -> bytes:
    """Pack a message with PQC support.

    This function automatically detects whether to use PQC or classical
    crypto based on the sender key type and recipient key types.

    Args:
        session: Askar session for key lookups
        to_verkeys: List of recipient verkeys (base58)
        from_key: Sender key (PQCKey or aries_askar.Key) or None for anoncrypt
        message: Message to pack (string or bytes)

    Returns:
        bytes: JWE-encoded packed message
    """
    # Detect crypto mode
    sender_is_pqc = _is_pqc_key(from_key) if from_key else False
    recipient_types = [_detect_recipient_key_type(vk) for vk in to_verkeys]

    # Check if any recipient is PQC
    any_pqc = sender_is_pqc or "pqc" in recipient_types
    all_pqc = sender_is_pqc and all(t == "pqc" for t in recipient_types)

    if any_pqc:
        LOGGER.info(f"Using PQC pack mode: sender_pqc={sender_is_pqc}, "
                   f"recipients={recipient_types}")
        return await _pack_pqc(session, to_verkeys, from_key, message)
    else:
        # Delegate to classical implementation
        LOGGER.debug("Using classical pack mode (ED25519/X25519)")
        from acapy_agent.askar.didcomm.v1 import pack_message as pack_classical

        # Convert message to bytes if needed
        message_bytes = message.encode("utf-8") if isinstance(message, str) else message
        return pack_classical(to_verkeys, from_key, message_bytes)


async def _pack_pqc(
    session: Session,
    to_verkeys: Sequence[str],
    from_key: Optional[Union[Key, PQCKey]],
    message: Union[str, bytes],
) -> bytes:
    """Pack a message using PQC algorithms (ML-KEM-768 + XChaCha20-Poly1305).

    Algorithm:
        1. Generate random CEK (Content Encryption Key) using ChaCha20-Poly1305
        2. For each recipient:
           - Fetch ML-KEM-768 public key
           - Encapsulate CEK using ML-KEM-768
           - Add JWE recipient with encrypted_key
        3. If authcrypt:
           - Sign CEK with ML-DSA-65
           - Add signature to protected header
        4. Encrypt message with CEK using ChaCha20-Poly1305
        5. Return JWE envelope

    Args:
        session: Askar session for key lookups
        to_verkeys: Recipient verkeys (base58)
        from_key: Sender key (PQCKey with ML-DSA-65 or ML-KEM-768) or None
        message: Message to encrypt

    Returns:
        bytes: JWE-encoded message
    """
    from acapy_agent.utils.jwe import JweEnvelope, JweRecipient, b64url
    from acapy_agent.wallet.util import bytes_to_b58, b58_to_bytes

    # Convert message to bytes
    message_bytes = message.encode("utf-8") if isinstance(message, str) else message

    # 1. Generate CEK (Content Encryption Key)
    cek = Key.generate(KeyAlg.C20P)  # ChaCha20-Poly1305
    cek_bytes = key_get_secret_bytes(cek._handle)

    # Get liboqs for KEM operations
    liboqs = get_liboqs()

    # 2. Prepare sender info for authcrypt
    sender_vk = None
    if from_key:
        if isinstance(from_key, PQCKey):
            sender_vk = bytes_to_b58(from_key.get_public_bytes()).encode("utf-8")
        else:
            sender_vk = bytes_to_b58(from_key.get_public_bytes()).encode("utf-8")

    # 3. Create JWE wrapper
    wrapper = JweEnvelope(with_protected_recipients=True, with_flatten_recipients=False)

    # 4. Encapsulate CEK for each recipient
    for target_vk in to_verkeys:
        # Decode recipient's public key from base58
        # Note: Unlike sender keys, recipient keys are NOT stored in our wallet!
        # The verkey is passed as a base58-encoded public key that we decode directly.

        # Detect key type based on length (same as pack_message_pqc)
        recipient_type = _detect_recipient_key_type(target_vk)

        if recipient_type == "pqc":
            # PQC path: Decode ML-KEM-768 public key from base58
            LOGGER.debug(f"Decoding ML-KEM-768 recipient key: {target_vk[:20]}...")
            target_public = b58_to_bytes(target_vk)

            if sender_vk:
                # Authcrypt mode: Encapsulate CEK + sign with sender
                ciphertext, shared_secret = liboqs.kem_encapsulate(target_public)

                # For authcrypt, we need to sign the ciphertext with sender's ML-DSA-65
                if isinstance(from_key, PQCKey) and from_key.algorithm == "ml-dsa-65":
                    signature = liboqs.ml_dsa_sign(
                        from_key.get_secret_bytes(),
                        ciphertext
                    )

                    wrapper.add_recipient(
                        JweRecipient(
                            encrypted_key=ciphertext,
                            header=OrderedDict([
                                ("kid", target_vk),
                                ("sender", b64url(sender_vk)),
                                ("sig", b64url(signature)),
                            ])
                        )
                    )
                else:
                    # Sender is not ML-DSA-65, can't do PQC authcrypt
                    raise ValueError("Authcrypt requires sender with ML-DSA-65 key")

                # Use shared_secret as CEK (for simplicity, in production use KDF)
                # Note: This is a simplified implementation!
                cek_bytes = shared_secret[:32]  # ChaCha20 needs 256-bit key
                cek = Key.from_secret_bytes(KeyAlg.C20P, cek_bytes)  # Recreate CEK from shared_secret!

            else:
                # Anoncrypt mode: Just encapsulate CEK
                ciphertext, shared_secret = liboqs.kem_encapsulate(target_public)

                wrapper.add_recipient(
                    JweRecipient(
                        encrypted_key=ciphertext,
                        header={"kid": target_vk}
                    )
                )

                # Use shared_secret as CEK
                cek_bytes = shared_secret[:32]
                cek = Key.from_secret_bytes(KeyAlg.C20P, cek_bytes)  # Recreate CEK from shared_secret!

        else:
            # Classical key (ED25519) - decode from base58 and convert to X25519
            LOGGER.debug(f"Decoding classical ED25519 recipient key: {target_vk[:20]}...")

            # Decode ED25519 public key from base58
            ed_public_bytes = b58_to_bytes(target_vk)

            # Convert ED25519 --> X25519 for ECDH
            from aries_askar import crypto_box
            target_xk = Key.from_public_bytes(KeyAlg.ED25519, ed_public_bytes).convert_key(KeyAlg.X25519)

            if sender_vk:
                # Classical authcrypt
                if isinstance(from_key, Key):
                    sender_xk = from_key.convert_key(KeyAlg.X25519)
                    enc_sender = crypto_box.crypto_box_seal(target_xk, sender_vk)
                    nonce = crypto_box.random_nonce()
                    enc_cek = crypto_box.crypto_box(target_xk, sender_xk, cek_bytes, nonce)

                    wrapper.add_recipient(
                        JweRecipient(
                            encrypted_key=enc_cek,
                            header=OrderedDict([
                                ("kid", target_vk),
                                ("sender", b64url(enc_sender)),
                                ("iv", b64url(nonce)),
                            ])
                        )
                    )
                else:
                    raise ValueError("Classical authcrypt requires classical sender key")
            else:
                # Classical anoncrypt
                enc_cek = crypto_box.crypto_box_seal(target_xk, cek_bytes)
                wrapper.add_recipient(
                    JweRecipient(
                        encrypted_key=enc_cek,
                        header={"kid": target_vk}
                    )
                )

    # 5. Set protected header
    alg = "PQC-Authcrypt" if from_key else "PQC-Anoncrypt"
    wrapper.set_protected(
        OrderedDict([
            ("enc", "xchacha20poly1305_ietf"),
            ("typ", "JWM/1.0"),
            ("alg", alg),
        ])
    )

    # 6. Encrypt message with CEK
    enc = cek.aead_encrypt(message_bytes, aad=wrapper.protected_bytes)
    ciphertext, tag, nonce = enc.parts
    wrapper.set_payload(ciphertext, nonce, tag)

    # 7. Serialize to JSON
    return wrapper.to_json().encode("utf-8")


async def unpack_message_pqc(
    session: Session,
    enc_message: bytes
) -> Tuple[str, str, str]:
    """Unpack a message with PQC support.

    This function automatically detects whether the message was packed with
    PQC or classical crypto based on the "alg" field in the JWE protected header.

    Args:
        session: Askar session for key lookups
        enc_message: JWE-encoded message

    Returns:
        Tuple[str, str, str]: (message, sender_verkey, recipient_verkey)
    """
    from acapy_agent.utils.jwe import JweEnvelope
    from acapy_agent.wallet.base import WalletError
    from marshmallow import ValidationError

    try:
        wrapper = JweEnvelope.from_json(enc_message)
    except ValidationError:
        raise WalletError("Invalid packed message")

    alg = wrapper.protected.get("alg")

    # Detect PQC mode
    if alg in ("PQC-Authcrypt", "PQC-Anoncrypt"):
        LOGGER.info(f"Using PQC unpack mode: alg={alg}")
        return await _unpack_pqc(session, wrapper)
    elif alg in ("Authcrypt", "Anoncrypt"):
        # Delegate to classical implementation
        LOGGER.debug(f"Using classical unpack mode: alg={alg}")
        from acapy_agent.askar.didcomm.v1 import unpack_message as unpack_classical
        return await unpack_classical(session, enc_message)
    else:
        raise WalletError(f"Unsupported pack algorithm: {alg}")


async def _unpack_pqc(
    session: Session,
    wrapper
) -> Tuple[str, str, str]:
    """Unpack a PQC-encrypted message.

    Algorithm:
        1. Extract recipients from JWE
        2. Try each recipient until we find one we can decrypt:
           - Fetch our ML-KEM-768 secret key
           - Decapsulate CEK using ML-KEM-768
           - If authcrypt, verify signature with sender's ML-DSA-65
        3. Decrypt message with CEK using ChaCha20-Poly1305
        4. Return (message, sender_vk, recipient_vk)

    Args:
        session: Askar session for key lookups
        wrapper: JweEnvelope object

    Returns:
        Tuple[str, str, str]: (message, sender_verkey, recipient_verkey)
    """
    from acapy_agent.wallet.base import WalletError
    from acapy_agent.utils.jwe import b64url

    alg = wrapper.protected.get("alg")
    is_authcrypt = alg == "PQC-Authcrypt"

    # Get liboqs for KEM operations
    liboqs = get_liboqs()

    # Parse recipients manually (don't use extract_pack_recipients - it's classical-only)
    # PQC format: {"kid": "...", "sender": "...", "sig": "..."}
    # Classical format: {"kid": "...", "sender": "...", "iv": "..."}
    # NOTE: wrapper.recipients returns JweRecipient objects, not dicts
    recips = {}
    for recipient in wrapper.recipients:
        kid = recipient.header.get("kid")
        if kid:
            recips[kid] = {
                "key": recipient.encrypted_key,
                "sender": recipient.header.get("sender"),
                "sig": recipient.header.get("sig"),  # PQC: ML-DSA-65 signature
                "iv": recipient.header.get("iv"),    # Classical: nonce
                "nonce": recipient.header.get("iv"), # Alias for compatibility
            }

    # Try to decrypt for each recipient we have a key for
    cek_bytes, sender_vk, recip_vk = None, None, None

    LOGGER.error("=" * 80)
    LOGGER.error("[PQC UNPACK DEBUG] Starting recipient decryption loop")
    LOGGER.error(f"[PQC UNPACK DEBUG] Found {len(recips)} recipients in JWE")
    LOGGER.error(f"[PQC UNPACK DEBUG] Recipient KIDs: {list(recips.keys())}")

    for recip_verkey, recip_data in recips.items():
        LOGGER.error(f"[PQC UNPACK DEBUG] Trying recipient: {recip_verkey[:60] if len(recip_verkey) > 60 else recip_verkey}...")

        # Try to fetch our secret key
        LOGGER.error(f"[PQC UNPACK DEBUG] Calling session.fetch_key({recip_verkey[:60]}...)")
        recip_key_entry = await session.fetch_key(recip_verkey)
        LOGGER.error(f"[PQC UNPACK DEBUG] fetch_key result: {recip_key_entry}")

        if recip_key_entry:
            # Handle both KeyEntry wrapper (classical) and direct PQCKey
            if isinstance(recip_key_entry, PQCKey):
                recip_key = recip_key_entry  # Already a PQCKey
            else:
                recip_key = recip_key_entry.key  # KeyEntry wrapper

            if isinstance(recip_key, PQCKey) and recip_key.algorithm == "ml-kem-768":
                # PQC path: ML-KEM-768 decapsulation
                secret_key = recip_key.get_secret_bytes()
                ciphertext = recip_data["key"]  # encrypted_key from JWE recipient

                try:
                    # Decapsulate to get shared secret (used as CEK)
                    shared_secret = liboqs.kem_decapsulate(secret_key, ciphertext)
                    cek_bytes = shared_secret[:32]  # ChaCha20 needs 256-bit key

                    # Check for authcrypt signature
                    if is_authcrypt:
                        sig = recip_data.get("sig")
                        sender_vk_b64 = recip_data.get("sender")

                        if not sig or not sender_vk_b64:
                            raise WalletError("Authcrypt message missing signature or sender")

                        # Decode sender verkey and signature
                        import base64
                        from acapy_agent.wallet.util import b58_to_bytes

                        sender_vk = base64.urlsafe_b64decode(sender_vk_b64 + "==").decode("utf-8")
                        signature = base64.urlsafe_b64decode(sig + "==")

                        # Extract sender's ML-DSA-65 public key directly from message
                        # (Like classical ED25519: don't fetch from wallet, use from message!)
                        sender_public = b58_to_bytes(sender_vk)

                        # Verify signature
                        LOGGER.error(f"[PQC UNPACK DEBUG] Verifying ML-DSA-65 signature...")
                        LOGGER.error(f"[PQC UNPACK DEBUG]   sender_vk (base58): {sender_vk[:60]}...")
                        LOGGER.error(f"[PQC UNPACK DEBUG]   sender_public (bytes): {len(sender_public)} bytes")
                        if not liboqs.ml_dsa_verify(sender_public, ciphertext, signature):
                            raise WalletError("Invalid ML-DSA-65 signature in authcrypt")
                        LOGGER.error(f"[PQC UNPACK DEBUG]   ✅ Signature verified!")

                    recip_vk = recip_verkey
                    LOGGER.error(f"[PQC UNPACK DEBUG] ✅✅✅ SUCCESS! recip_vk set to: {recip_vk[:60] if len(recip_vk) > 60 else recip_vk}")
                    break  # Success!

                except Exception as e:
                    LOGGER.error(f"[PQC UNPACK DEBUG] ❌ Decryption failed: {e}")
                    LOGGER.debug(f"Failed to decrypt for recipient {recip_verkey[:20]}...: {e}")
                    continue

            else:
                # Classical key - should not happen in pure PQC mode
                LOGGER.warning(f"Recipient {recip_verkey[:20]}... is classical, "
                              f"trying classical crypto_box")

                # Fallback to classical decryption
                from acapy_agent.askar.didcomm.v1 import _extract_payload_key
                try:
                    cek_bytes, sender_vk = _extract_payload_key(recip_data, recip_key)
                    recip_vk = recip_verkey
                    break
                except Exception as e:
                    LOGGER.error(f"[PQC UNPACK DEBUG] ❌ Classical decryption failed: {e}")
                    LOGGER.debug(f"Classical decrypt failed for {recip_verkey[:20]}...: {e}")
                    continue
        else:
            LOGGER.error(f"[PQC UNPACK DEBUG] ⚠️  No key found for recipient {recip_verkey[:60] if len(recip_verkey) > 60 else recip_verkey}")

    LOGGER.error(f"[PQC UNPACK DEBUG] Loop finished. recip_vk = {recip_vk}")
    LOGGER.error("=" * 80)

    if not cek_bytes:
        raise WalletError(f"No corresponding recipient key found in {tuple(recips.keys())}")

    if not sender_vk and is_authcrypt:
        raise WalletError("Sender public key not provided for Authcrypt message")

    # Decrypt message with CEK
    cek = Key.from_secret_bytes(KeyAlg.C20P, cek_bytes)
    message = cek.aead_decrypt(
        wrapper.ciphertext,
        nonce=wrapper.iv,
        tag=wrapper.tag,
        aad=wrapper.protected_bytes,
    )

    # Return in ACA-Py format: (message, from_verkey, to_verkey)
    # from_verkey = sender, to_verkey = recipient
    return message.decode("utf-8"), sender_vk, recip_vk

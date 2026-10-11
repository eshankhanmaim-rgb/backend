"""
Cryptographic helpers using PyNaCl and cryptography.
- Ed25519: sign loader responses (private key server-only, public key in binary)
- X25519 + HKDF-SHA256: per-session key derivation
- AES-256-GCM: encrypt license keys at rest
"""
import os
import struct
from typing import Tuple

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import RawEncoder
import nacl.exceptions

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from app.core.config import get_settings


# ---------------------------------------------------------------------------
# Ed25519 — loader response signing
# ---------------------------------------------------------------------------

def get_signing_key() -> SigningKey:
    """Load the Ed25519 signing key from config."""
    key_bytes = get_settings().ed25519_private_key_bytes
    # PyNaCl SigningKey expects the 32-byte seed
    if len(key_bytes) == 64:
        key_bytes = key_bytes[:32]  # libsodium extended format: seed || public
    return SigningKey(key_bytes)


def sign_response(body_bytes: bytes) -> str:
    """
    Sign raw response bytes with Ed25519.
    Returns base64url-encoded signature (no padding) suitable for X-Signature header.
    """
    import base64
    sk = get_signing_key()
    signed = sk.sign(body_bytes, encoder=RawEncoder)
    # signed[:64] is the signature, signed[64:] is the message
    signature_bytes = signed[:64]
    return base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode()


def verify_signature(body_bytes: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature (for testing/internal use)."""
    import base64
    try:
        # Add padding
        padding = 4 - len(signature_b64) % 4
        if padding != 4:
            signature_b64 += "=" * padding
        sig_bytes = base64.urlsafe_b64decode(signature_b64)
        vk_bytes = get_settings().ed25519_public_key_bytes
        if len(vk_bytes) == 64:
            vk_bytes = vk_bytes[32:]  # public key part
        vk = VerifyKey(vk_bytes)
        vk.verify(body_bytes, sig_bytes)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# X25519 + HKDF-SHA256 — per-session key derivation
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an X25519 ephemeral keypair.
    Returns (private_key_bytes_32, public_key_bytes_32).
    """
    sk = PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)


def derive_session_key(
    server_private_key_bytes: bytes,
    client_public_key_bytes: bytes,
    server_public_key_bytes: bytes,
    client_public_key_bytes_for_info: bytes,
) -> bytes:
    """
    Derive a 32-byte session key using X25519 ECDH + HKDF-SHA256.
    
    HKDF info = b"pruvate-session-v1" || server_pub || client_pub
    This binds the key to both parties and prevents key reuse attacks.
    """
    sk = PrivateKey(server_private_key_bytes)
    pk = PublicKey(client_public_key_bytes)
    box = Box(sk, pk)
    shared_secret = box.shared_key()  # 32-byte X25519 output

    info = b"pruvate-session-v1" + server_public_key_bytes + client_public_key_bytes_for_info

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# AES-256-GCM — license key encryption at rest
# ---------------------------------------------------------------------------

def encrypt_license_key(raw_key: str) -> str:
    """
    Encrypt a raw license key string with AES-256-GCM.
    Returns: hex(nonce || tag || ciphertext)  (12 + 16 + len bytes)
    """
    enc_key = get_settings().license_encryption_key_bytes
    aesgcm = AESGCM(enc_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, raw_key.encode("utf-8"), None)
    return (nonce + ct).hex()


def decrypt_license_key(encrypted_hex: str) -> str:
    """
    Decrypt an AES-256-GCM encrypted license key.
    Input: hex(nonce || tag || ciphertext)
    """
    enc_key = get_settings().license_encryption_key_bytes
    aesgcm = AESGCM(enc_key)
    data = bytes.fromhex(encrypted_hex)
    nonce = data[:12]
    ct = data[12:]
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode("utf-8")


def compute_key_lookup(raw_key: str) -> str:
    """
    HMAC-SHA256 of the raw license key using the dedicated HMAC key.
    Used for database lookups without storing the plaintext key.
    """
    import hmac as _hmac
    import hashlib
    hmac_key = get_settings().license_hmac_key_bytes
    return _hmac.new(hmac_key, raw_key.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Resource key generation (per-session, required to unlock loader functionality)
# ---------------------------------------------------------------------------

def generate_resource_key(session_id: str, uid: str) -> str:
    """
    Generate a deterministic resource key for a loader session.
    The key is derived from session_id + uid using HKDF so it can be
    validated server-side on subsequent requests.
    """
    import hashlib, hmac as _hmac
    secret = get_settings().license_hmac_key_bytes  # reuse as session resource key derivation key
    data = f"{session_id}:{uid}".encode()
    return _hmac.new(secret, data, hashlib.sha256).hexdigest()

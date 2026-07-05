"""Cryptographic primitives for SecureVault PKI.

This module provides all low-level cryptographic operations as pure functions.
It is the only module that directly interfaces with the `cryptography` library,
ensuring a single point of audit for all crypto operations.

All randomness is sourced from os.urandom() (CSPRNG). No hardcoded keys are used.
"""

import base64
import hmac
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def aes_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM authenticated encryption.

    AES-256-GCM was chosen because it provides both confidentiality and integrity
    in a single operation (AEAD), preventing tampering without additional MAC layers.
    The 12-byte IV is recommended by NIST SP 800-38D for GCM mode, and the 16-byte
    authentication tag provides 128-bit integrity protection.

    Args:
        plaintext: Data to encrypt (arbitrary length, may be empty).
        key: 256-bit (32-byte) encryption key.
        aad: Additional authenticated data (optional). Authenticated but not encrypted,
             useful for binding ciphertext to context (e.g., message headers).

    Returns:
        Tuple of (iv, ciphertext, tag) where:
            - iv: 12-byte initialization vector (randomly generated via CSPRNG)
            - ciphertext: encrypted data (same length as plaintext)
            - tag: 16-byte GCM authentication tag

    Raises:
        ValueError: If key is not exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError(
            f"AES-256-GCM requires a 32-byte key, got {len(key)} bytes"
        )

    # Generate a 96-bit IV from CSPRNG as recommended by NIST SP 800-38D
    iv = os.urandom(12)

    # AESGCM handles encryption and tag generation internally
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)

    # The cryptography library appends the 16-byte tag to the ciphertext
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return (iv, ciphertext, tag)


def aes_decrypt(ciphertext: bytes, iv: bytes, tag: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Decrypt ciphertext using AES-256-GCM authenticated decryption.

    AES-256-GCM decryption verifies the authentication tag before returning
    plaintext, ensuring that any tampering with the ciphertext, IV, or tag
    is detected. This prevents chosen-ciphertext attacks.

    Args:
        ciphertext: Encrypted data.
        iv: 12-byte initialization vector used during encryption.
        tag: 16-byte GCM authentication tag.
        key: 256-bit (32-byte) decryption key (must match encryption key).
        aad: Additional authenticated data (must match the AAD used during encryption).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If key is not exactly 32 bytes.
        cryptography.exceptions.InvalidTag: If authentication fails (tampered data,
            wrong key, or mismatched AAD).
    """
    if len(key) != 32:
        raise ValueError(
            f"AES-256-GCM requires a 32-byte key, got {len(key)} bytes"
        )

    # Reconstruct the combined ciphertext+tag format expected by the library
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag

    # Decryption verifies the tag; raises InvalidTag on failure
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, aad)

    return plaintext


def rsa_keygen(key_size: int = 4096) -> Tuple[bytes, bytes]:
    """Generate an RSA key pair.

    RSA-4096 was chosen to provide a security level exceeding 128 bits,
    suitable for long-term digital signatures. The public exponent 65537
    is the standard choice balancing security and verification performance.

    Args:
        key_size: RSA key size in bits. Defaults to 4096 for high security.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes, both in PEM encoding.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (private_key_pem, public_key_pem)


def ecdh_keygen(curve: str = "secp384r1") -> Tuple[bytes, bytes]:
    """Generate an ECC key pair for ECDH key agreement.

    P-384 (secp384r1) was chosen to provide approximately 192-bit security,
    exceeding the 128-bit minimum while offering good performance for
    ephemeral key generation in hybrid encryption schemes.

    Args:
        curve: The elliptic curve to use. Defaults to "secp384r1" (NIST P-384).

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes, both in PEM encoding.

    Raises:
        ValueError: If an unsupported curve is specified.
    """
    curve_map = {
        "secp384r1": ec.SECP384R1(),
    }

    if curve not in curve_map:
        raise ValueError(f"Unsupported curve: {curve}. Supported: {list(curve_map.keys())}")

    private_key = ec.generate_private_key(curve_map[curve])

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (private_key_pem, public_key_pem)


def rsa_sign(message: bytes, private_key_pem: bytes) -> str:
    """Sign a message using RSA-PSS with SHA-256.

    RSA-PSS (Probabilistic Signature Scheme) was chosen over PKCS#1 v1.5
    because PSS has a formal security proof in the random oracle model.
    Maximum salt length maximizes the randomization of signatures, providing
    the strongest possible security for a given key size.

    Args:
        message: The message bytes to sign (typically a hash of the document).
        private_key_pem: PEM-encoded RSA private key.

    Returns:
        Base64url-encoded signature string.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None
    )

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return b64_encode(signature)


def rsa_verify(message: bytes, signature_b64: str, public_key_pem: bytes) -> bool:
    """Verify an RSA-PSS signature.

    Returns False instead of raising an exception for invalid signatures,
    preventing timing-based information leakage about which verification
    step failed. This follows the principle of fail-secure design.

    Args:
        message: The original message bytes that were signed.
        signature_b64: Base64url-encoded signature to verify.
        public_key_pem: PEM-encoded RSA public key corresponding to the signer.

    Returns:
        True if the signature is valid, False otherwise. Never raises for invalid signatures.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        signature = b64_decode(signature_b64)

        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def ecdh_derive_shared_secret(private_key_pem: bytes, public_key_pem: bytes) -> bytes:
    """Derive a shared secret using ECDH key agreement.

    ECDH (Elliptic Curve Diffie-Hellman) enables two parties to independently
    derive the same shared secret using only their own private key and the
    other party's public key, without transmitting the secret. This is the
    foundation for forward-secret hybrid encryption.

    Args:
        private_key_pem: PEM-encoded ECC private key (one party).
        public_key_pem: PEM-encoded ECC public key (the other party).

    Returns:
        Raw shared secret bytes (48 bytes for P-384 curve).
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None
    )
    public_key = serialization.load_pem_public_key(public_key_pem)

    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    return shared_secret


def hkdf_expand(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a key from a shared secret using HKDF-SHA256.

    HKDF (HMAC-based Key Derivation Function) was chosen because it provides
    a theoretically sound extract-then-expand paradigm (RFC 5869). The salt
    and info parameters enable context separation, allowing derivation of
    multiple independent keys from a single shared secret.

    Args:
        shared_secret: Input keying material (e.g., from ECDH).
        salt: Optional salt value for the extract step. Use different salts
              to derive independent keys from the same shared secret.
        info: Context and application-specific information for the expand step.
              Binds the derived key to a specific purpose (e.g., b"encryption").
        length: Desired output key length in bytes. Defaults to 32 (256 bits).

    Returns:
        Derived key of the specified length.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    )

    derived_key = hkdf.derive(shared_secret)

    return derived_key


def b64_encode(data: bytes) -> str:
    """Encode bytes to a URL-safe base64 string.

    URL-safe base64 is used throughout SecureVault to ensure encoded data
    can be safely embedded in JSON, URLs, and filenames without escaping issues.
    The padding characters ('=') are retained for unambiguous decoding.

    Args:
        data: Raw bytes to encode.

    Returns:
        URL-safe base64-encoded string.
    """
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    """Decode a URL-safe base64 string to bytes.

    Handles both padded and unpadded base64 input for interoperability.

    Args:
        data: URL-safe base64-encoded string.

    Returns:
        Decoded raw bytes.
    """
    return base64.urlsafe_b64decode(data)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Perform a timing-safe comparison of two byte strings.

    Uses hmac.compare_digest to prevent timing side-channel attacks where
    an attacker could determine the number of matching prefix bytes by
    measuring comparison time. This is critical for signature and MAC
    verification to prevent adaptive forgery attacks.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if and only if a equals b, with constant-time execution
        regardless of where the first difference occurs.
    """
    return hmac.compare_digest(a, b)

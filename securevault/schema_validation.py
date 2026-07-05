"""Data schema validation for SecureVault PKI.

This module provides strict validation functions for all data structures
used in the SecureVault PKI system: certificates, detached signatures,
encrypted messages, and key storage files.

Validation is lightweight — it checks types, sizes, and format constraints
but does not verify cryptographic validity (e.g., it checks that a signature
field is valid base64, not that the signature mathematically verifies).

Each validator returns a tuple of (is_valid: bool, reason: str) where
reason is "valid" on success or a specific failure description on error.
"""

import time
from typing import Tuple

from securevault.crypto_utils import b64_decode


def validate_certificate(cert: dict) -> Tuple[bool, str]:
    """Validate a certificate dictionary against the certificate schema.

    Checks that all required fields are present and conform to the expected
    types and constraints. This ensures malformed certificates are rejected
    early with clear error messages before any cryptographic operations.

    Validation rules:
        - serial: must be a positive integer
        - subject: must be a non-empty string, max 256 characters
        - key_type: must be "rsa" or "ecc"
        - public_key: must be a valid PEM string (starts with "-----BEGIN")
        - signature: must be valid base64 if non-empty
        - not_before < not_after (temporal ordering)

    Args:
        cert: Certificate dictionary to validate.

    Returns:
        (True, "valid") if all checks pass, or
        (False, "specific reason") describing the first validation failure.
    """
    # Check serial is a positive integer
    serial = cert.get("serial")
    if not isinstance(serial, int) or serial <= 0:
        return (False, "serial must be a positive integer")

    # Check subject is non-empty string, max 256 chars
    subject = cert.get("subject")
    if not isinstance(subject, str) or not subject.strip():
        return (False, "subject must be a non-empty string")
    if len(subject) > 256:
        return (False, "subject must be at most 256 characters")

    # Check key_type is "rsa" or "ecc"
    key_type = cert.get("key_type")
    if key_type not in ("rsa", "ecc"):
        return (False, "key_type must be 'rsa' or 'ecc'")

    # Check public_key is a valid PEM string
    public_key = cert.get("public_key")
    if not isinstance(public_key, str) or not public_key.strip().startswith("-----BEGIN"):
        return (False, "public_key must be a valid PEM string")

    # Check signature is valid base64 (if not empty)
    signature = cert.get("signature")
    if not isinstance(signature, str):
        return (False, "signature must be a string")
    if signature:
        try:
            b64_decode(signature)
        except Exception:
            return (False, "signature must be valid base64")

    # Check temporal ordering: not_before < not_after
    not_before = cert.get("not_before")
    not_after = cert.get("not_after")
    if not isinstance(not_before, (int, float)):
        return (False, "not_before must be a number")
    if not isinstance(not_after, (int, float)):
        return (False, "not_after must be a number")
    if not_before >= not_after:
        return (False, "not_before must be less than not_after")

    return (True, "valid")


def validate_signature_payload(sig: dict) -> Tuple[bool, str]:
    """Validate a detached signature payload against the signature schema.

    Checks that the signature payload conforms to the expected format,
    ensuring that malformed signatures are rejected before verification
    is attempted.

    Validation rules:
        - version: must equal 1
        - algorithm: must be "RSA-PSS-SHA256"
        - signature: must be valid base64
        - signer_cert: must be a dict with required certificate fields
        - timestamp: must be a number and not in the future

    Args:
        sig: Signature payload dictionary to validate.

    Returns:
        (True, "valid") if all checks pass, or
        (False, "specific reason") describing the first validation failure.
    """
    # Check version == 1
    version = sig.get("version")
    if version != 1:
        return (False, "version must be 1")

    # Check algorithm == "RSA-PSS-SHA256"
    algorithm = sig.get("algorithm")
    if algorithm != "RSA-PSS-SHA256":
        return (False, "algorithm must be 'RSA-PSS-SHA256'")

    # Check signature is valid base64
    signature = sig.get("signature")
    if not isinstance(signature, str):
        return (False, "signature must be a string")
    try:
        b64_decode(signature)
    except Exception:
        return (False, "signature must be valid base64")

    # Check signer_cert is a dict with required fields
    signer_cert = sig.get("signer_cert")
    if not isinstance(signer_cert, dict):
        return (False, "signer_cert must be a dictionary")
    required_cert_fields = ("subject", "public_key", "issuer", "serial",
                            "not_before", "not_after", "signature")
    for field in required_cert_fields:
        if field not in signer_cert:
            return (False, f"signer_cert missing required field '{field}'")

    # Check timestamp is a number and not in the future
    timestamp = sig.get("timestamp")
    if not isinstance(timestamp, (int, float)):
        return (False, "timestamp must be a number")
    if timestamp > time.time():
        return (False, "timestamp must not be in the future")

    return (True, "valid")


def validate_encrypted_message(msg: dict) -> Tuple[bool, str]:
    """Validate an encrypted message dictionary against the encrypted message schema.

    Checks that the encrypted message has all required fields with correct
    sizes and formats. This catches malformed encrypted data early before
    any decryption is attempted.

    Validation rules:
        - version: must equal 1
        - algorithm: must be "ECDH-P384+HKDF-SHA256+AES-256-GCM"
        - iv_b64: must decode to exactly 12 bytes
        - tag_b64: must decode to exactly 16 bytes
        - nonce_b64: must decode to exactly 16 bytes
        - ephemeral_pub_b64: must decode to valid PEM bytes (starts with "-----BEGIN")
        - ciphertext_b64: must decode to non-empty bytes
        - timestamp: must be a number

    Args:
        msg: Encrypted message dictionary to validate.

    Returns:
        (True, "valid") if all checks pass, or
        (False, "specific reason") describing the first validation failure.
    """
    # Check version == 1
    version = msg.get("version")
    if version != 1:
        return (False, "version must be 1")

    # Check algorithm
    algorithm = msg.get("algorithm")
    if algorithm != "ECDH-P384+HKDF-SHA256+AES-256-GCM":
        return (False, "algorithm must be 'ECDH-P384+HKDF-SHA256+AES-256-GCM'")

    # Check iv_b64 decodes to exactly 12 bytes
    iv_b64 = msg.get("iv_b64")
    if not isinstance(iv_b64, str):
        return (False, "iv_b64 must be a string")
    try:
        iv_bytes = b64_decode(iv_b64)
    except Exception:
        return (False, "iv_b64 must be valid base64")
    if len(iv_bytes) != 12:
        return (False, "iv_b64 must decode to exactly 12 bytes")

    # Check tag_b64 decodes to exactly 16 bytes
    tag_b64 = msg.get("tag_b64")
    if not isinstance(tag_b64, str):
        return (False, "tag_b64 must be a string")
    try:
        tag_bytes = b64_decode(tag_b64)
    except Exception:
        return (False, "tag_b64 must be valid base64")
    if len(tag_bytes) != 16:
        return (False, "tag_b64 must decode to exactly 16 bytes")

    # Check nonce_b64 decodes to exactly 16 bytes
    nonce_b64 = msg.get("nonce_b64")
    if not isinstance(nonce_b64, str):
        return (False, "nonce_b64 must be a string")
    try:
        nonce_bytes = b64_decode(nonce_b64)
    except Exception:
        return (False, "nonce_b64 must be valid base64")
    if len(nonce_bytes) != 16:
        return (False, "nonce_b64 must decode to exactly 16 bytes")

    # Check ephemeral_pub_b64 decodes to valid PEM bytes
    ephemeral_pub_b64 = msg.get("ephemeral_pub_b64")
    if not isinstance(ephemeral_pub_b64, str):
        return (False, "ephemeral_pub_b64 must be a string")
    try:
        ephemeral_pub_bytes = b64_decode(ephemeral_pub_b64)
    except Exception:
        return (False, "ephemeral_pub_b64 must be valid base64")
    if not ephemeral_pub_bytes.startswith(b"-----BEGIN"):
        return (False, "ephemeral_pub_b64 must decode to valid PEM bytes")

    # Check ciphertext_b64 decodes to non-empty bytes
    ciphertext_b64 = msg.get("ciphertext_b64")
    if not isinstance(ciphertext_b64, str):
        return (False, "ciphertext_b64 must be a string")
    try:
        ciphertext_bytes = b64_decode(ciphertext_b64)
    except Exception:
        return (False, "ciphertext_b64 must be valid base64")
    if len(ciphertext_bytes) == 0:
        return (False, "ciphertext_b64 must decode to non-empty bytes")

    # Check timestamp is a number
    timestamp = msg.get("timestamp")
    if not isinstance(timestamp, (int, float)):
        return (False, "timestamp must be a number")

    return (True, "valid")


def validate_key_storage(storage: dict) -> Tuple[bool, str]:
    """Validate a key storage dictionary against the key storage schema.

    Checks that the encrypted private key storage file conforms to the
    expected format with correct sizes. This ensures malformed key files
    are rejected before decryption is attempted.

    Validation rules:
        - version: must equal 1
        - key_type: must be "rsa" or "ecc"
        - algorithm: must be "PBKDF2-SHA256+AES-256-GCM"
        - iterations: must be >= 100000
        - salt_b64: must decode to exactly 16 bytes
        - iv_b64: must decode to exactly 12 bytes
        - tag_b64: must decode to exactly 16 bytes
        - encrypted_key_b64: must decode to non-empty bytes

    Args:
        storage: Key storage dictionary to validate.

    Returns:
        (True, "valid") if all checks pass, or
        (False, "specific reason") describing the first validation failure.
    """
    # Check version == 1
    version = storage.get("version")
    if version != 1:
        return (False, "version must be 1")

    # Check key_type is "rsa" or "ecc"
    key_type = storage.get("key_type")
    if key_type not in ("rsa", "ecc"):
        return (False, "key_type must be 'rsa' or 'ecc'")

    # Check algorithm
    algorithm = storage.get("algorithm")
    if algorithm != "PBKDF2-SHA256+AES-256-GCM":
        return (False, "algorithm must be 'PBKDF2-SHA256+AES-256-GCM'")

    # Check iterations >= 100000
    iterations = storage.get("iterations")
    if not isinstance(iterations, int) or iterations < 100000:
        return (False, "iterations must be an integer >= 100000")

    # Check salt_b64 decodes to exactly 16 bytes
    salt_b64 = storage.get("salt_b64")
    if not isinstance(salt_b64, str):
        return (False, "salt_b64 must be a string")
    try:
        salt_bytes = b64_decode(salt_b64)
    except Exception:
        return (False, "salt_b64 must be valid base64")
    if len(salt_bytes) != 16:
        return (False, "salt_b64 must decode to exactly 16 bytes")

    # Check iv_b64 decodes to exactly 12 bytes
    iv_b64 = storage.get("iv_b64")
    if not isinstance(iv_b64, str):
        return (False, "iv_b64 must be a string")
    try:
        iv_bytes = b64_decode(iv_b64)
    except Exception:
        return (False, "iv_b64 must be valid base64")
    if len(iv_bytes) != 12:
        return (False, "iv_b64 must decode to exactly 12 bytes")

    # Check tag_b64 decodes to exactly 16 bytes
    tag_b64 = storage.get("tag_b64")
    if not isinstance(tag_b64, str):
        return (False, "tag_b64 must be a string")
    try:
        tag_bytes = b64_decode(tag_b64)
    except Exception:
        return (False, "tag_b64 must be valid base64")
    if len(tag_bytes) != 16:
        return (False, "tag_b64 must decode to exactly 16 bytes")

    # Check encrypted_key_b64 decodes to non-empty bytes
    encrypted_key_b64 = storage.get("encrypted_key_b64")
    if not isinstance(encrypted_key_b64, str):
        return (False, "encrypted_key_b64 must be a string")
    try:
        encrypted_key_bytes = b64_decode(encrypted_key_b64)
    except Exception:
        return (False, "encrypted_key_b64 must be valid base64")
    if len(encrypted_key_bytes) == 0:
        return (False, "encrypted_key_b64 must decode to non-empty bytes")

    return (True, "valid")

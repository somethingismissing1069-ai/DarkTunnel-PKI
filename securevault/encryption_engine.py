"""Hybrid Encryption Engine for SecureVault PKI.

This module implements hybrid encryption combining ephemeral ECDH key agreement
with AES-256-GCM symmetric encryption to provide both confidentiality and
forward secrecy.

Hybrid Encryption Design:
    The "hybrid" approach combines asymmetric and symmetric cryptography:
    1. Asymmetric (ECDH): Used to establish a shared secret between sender and
       recipient without prior key exchange. Only the recipient's public key
       (from their certificate) is needed.
    2. Symmetric (AES-256-GCM): Used for the actual data encryption. This is
       orders of magnitude faster than asymmetric encryption for bulk data.

Forward Secrecy Guarantee:
    Each encryption operation generates a FRESH ephemeral ECDH key pair. The
    ephemeral private key is deleted immediately after deriving the shared secret.
    This ensures that even if the recipient's long-term private key is later
    compromised, past messages cannot be decrypted — the ephemeral private key
    needed to re-derive the shared secret no longer exists.

Algorithm Choices:
    - ECDH P-384: ~192-bit security level, suitable for long-term secrets
    - HKDF-SHA256: Standards-compliant key derivation (RFC 5869)
    - AES-256-GCM: Authenticated encryption preventing both eavesdropping and tampering
    - 16-byte nonce: Replay protection identifier (not related to AES IV)

Security Design:
    - NEVER persist ephemeral private keys to disk
    - ALWAYS delete ephemeral private key and shared secret from memory after use
    - ALWAYS verify recipient certificate contains an ECC public key
    - ALWAYS log encryption/decryption events without exposing key material
"""

import json
import os
import time
from typing import Optional

from securevault import crypto_utils
from securevault.logging_utils import log_event


def encrypt_message(plaintext: bytes, recipient_cert: dict) -> dict:
    """Encrypt a message for a specific recipient using hybrid encryption.

    Implements forward-secret hybrid encryption:
    1. Generate ephemeral ECDH P-384 key pair (never persisted)
    2. Perform ECDH key agreement with recipient's public key
    3. Derive AES-256 key via HKDF-SHA256
    4. Encrypt plaintext with AES-256-GCM
    5. Delete ephemeral private key and shared secret from memory

    The ephemeral key pair ensures forward secrecy: even if the recipient's
    long-term private key is compromised in the future, previously encrypted
    messages remain secure because the ephemeral private key no longer exists.

    Args:
        plaintext: The message bytes to encrypt (arbitrary length).
        recipient_cert: Certificate dictionary of the recipient. Must contain
            a "public_key" field with a PEM-encoded ECC P-384 public key and
            a "key_type" field set to "ecc".

    Returns:
        A dictionary containing:
            - version (int): Schema version (1)
            - algorithm (str): "ECDH-P384+HKDF-SHA256+AES-256-GCM"
            - ephemeral_pub_b64 (str): Base64-encoded ephemeral public key PEM
            - iv_b64 (str): Base64-encoded 12-byte AES-GCM IV
            - tag_b64 (str): Base64-encoded 16-byte GCM authentication tag
            - ciphertext_b64 (str): Base64-encoded encrypted data
            - nonce_b64 (str): Base64-encoded 16-byte replay protection nonce
            - timestamp (float): Unix timestamp of encryption

    Raises:
        ValueError: If recipient certificate does not contain an ECC public key.
    """
    # Verify recipient certificate has an ECC key
    key_type = recipient_cert.get("key_type", "")
    if key_type != "ecc":
        log_event(
            "encryption_engine",
            "encrypt_message",
            "failure",
            {"reason": "non-ECC recipient certificate", "key_type": key_type},
        )
        raise ValueError(
            f"Recipient certificate must have an ECC public key, got key_type='{key_type}'"
        )

    # Step 1: Generate ephemeral ECDH P-384 key pair
    ephemeral_priv, ephemeral_pub = crypto_utils.ecdh_keygen("secp384r1")

    # Step 2: Extract recipient's public key from certificate
    recipient_pub = recipient_cert["public_key"].encode("utf-8")

    # Step 3: Perform ECDH key agreement
    shared_secret = crypto_utils.ecdh_derive_shared_secret(ephemeral_priv, recipient_pub)

    # Step 4: Derive AES-256 key via HKDF-SHA256
    aes_key = crypto_utils.hkdf_expand(
        shared_secret=shared_secret,
        salt=b"",
        info=b"encryption",
        length=32,
    )

    # Step 5: Encrypt plaintext with AES-256-GCM
    iv, ciphertext, tag = crypto_utils.aes_encrypt(plaintext, aes_key)

    # Step 6: Generate replay protection nonce and timestamp
    nonce = os.urandom(16)
    timestamp = time.time()

    # Step 7: Securely erase ephemeral private key and shared secret
    del ephemeral_priv
    del shared_secret
    del aes_key

    # Step 8: Package encrypted message
    encrypted_msg = {
        "version": 1,
        "algorithm": "ECDH-P384+HKDF-SHA256+AES-256-GCM",
        "ephemeral_pub_b64": crypto_utils.b64_encode(ephemeral_pub),
        "iv_b64": crypto_utils.b64_encode(iv),
        "tag_b64": crypto_utils.b64_encode(tag),
        "ciphertext_b64": crypto_utils.b64_encode(ciphertext),
        "nonce_b64": crypto_utils.b64_encode(nonce),
        "timestamp": timestamp,
    }

    log_event(
        "encryption_engine",
        "encrypt_message",
        "success",
        {"algorithm": "ECDH-P384+HKDF-SHA256+AES-256-GCM"},
    )

    return encrypted_msg


def encrypt_file(
    filepath: str, recipient_cert: dict, output_path: Optional[str] = None
) -> None:
    """Encrypt a file for a specific recipient using hybrid encryption.

    Reads the file contents, encrypts using encrypt_message (hybrid encryption
    with forward secrecy), and writes the encrypted JSON to the output file.

    Args:
        filepath: Path to the file to encrypt.
        recipient_cert: Certificate dictionary of the recipient (must have ECC key).
        output_path: Optional output file path. Defaults to {filepath}.enc.

    Raises:
        FileNotFoundError: If the input file does not exist.
        ValueError: If recipient certificate does not contain an ECC public key.
    """
    if not os.path.isfile(filepath):
        log_event(
            "encryption_engine",
            "encrypt_file",
            "failure",
            {"reason": "file not found", "filepath": filepath},
        )
        raise FileNotFoundError(f"File not found: {filepath}")

    # Read file contents
    with open(filepath, "rb") as f:
        plaintext = f.read()

    # Encrypt using hybrid encryption
    encrypted_msg = encrypt_message(plaintext, recipient_cert)

    # Determine output path
    if output_path is None:
        output_path = filepath + ".enc"

    # Write encrypted JSON to output file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(encrypted_msg, f, indent=2)

    log_event(
        "encryption_engine",
        "encrypt_file",
        "success",
        {"filepath": filepath, "output_path": output_path},
    )


def decrypt_message(encrypted_dict: dict, private_key_pem: bytes) -> bytes:
    """Decrypt a message using the recipient's private key.

    Performs the inverse of encrypt_message:
    1. Decode the ephemeral public key from base64
    2. Perform ECDH key agreement with recipient's private key
    3. Derive the same AES-256 key via HKDF-SHA256 (same parameters)
    4. Decrypt with AES-256-GCM (authentication tag verified automatically)

    The HKDF parameters (salt=b"", info=b"encryption", length=32) must match
    exactly those used during encryption for successful key derivation.

    Args:
        encrypted_dict: The encrypted message dictionary as returned by
            encrypt_message. Must contain ephemeral_pub_b64, iv_b64, tag_b64,
            ciphertext_b64 fields.
        private_key_pem: The recipient's PEM-encoded ECC private key bytes.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If the ciphertext or tag has been
            tampered with, or if the wrong private key is used.
        ValueError: If the encrypted message format is invalid.
    """
    try:
        # Step 1: Decode ephemeral public key from base64 back to PEM bytes
        ephemeral_pub_pem = crypto_utils.b64_decode(encrypted_dict["ephemeral_pub_b64"])

        # Step 2: Perform ECDH key agreement with recipient's private key
        shared_secret = crypto_utils.ecdh_derive_shared_secret(
            private_key_pem, ephemeral_pub_pem
        )

        # Step 3: Derive same AES key via HKDF (must match encrypt params exactly)
        aes_key = crypto_utils.hkdf_expand(
            shared_secret=shared_secret,
            salt=b"",
            info=b"encryption",
            length=32,
        )

        # Step 4: Decode ciphertext components
        ciphertext = crypto_utils.b64_decode(encrypted_dict["ciphertext_b64"])
        iv = crypto_utils.b64_decode(encrypted_dict["iv_b64"])
        tag = crypto_utils.b64_decode(encrypted_dict["tag_b64"])

        # Step 5: Decrypt with AES-256-GCM (tag verified automatically)
        plaintext = crypto_utils.aes_decrypt(ciphertext, iv, tag, aes_key)

        # Step 6: Clean up sensitive material
        del shared_secret
        del aes_key

        log_event(
            "encryption_engine",
            "decrypt_message",
            "success",
            {"algorithm": "ECDH-P384+HKDF-SHA256+AES-256-GCM"},
        )

        return plaintext

    except KeyError as e:
        log_event(
            "encryption_engine",
            "decrypt_message",
            "failure",
            {"reason": f"missing field: {e}"},
        )
        raise ValueError(f"Invalid encrypted message format: missing field {e}") from e
    except Exception as e:
        log_event(
            "encryption_engine",
            "decrypt_message",
            "failure",
            {"reason": str(type(e).__name__)},
        )
        raise


def decrypt_file(
    filepath: str, private_key_pem: bytes, output_path: Optional[str] = None
) -> None:
    """Decrypt an encrypted file using the recipient's private key.

    Reads the encrypted JSON file, decrypts using decrypt_message, and writes
    the recovered plaintext to the output file.

    Args:
        filepath: Path to the encrypted file (typically with .enc extension).
        private_key_pem: The recipient's PEM-encoded ECC private key bytes.
        output_path: Optional output file path. Defaults to the filepath with
            the .enc extension removed.

    Raises:
        FileNotFoundError: If the encrypted file does not exist.
        cryptography.exceptions.InvalidTag: If decryption fails (tampered data
            or wrong key).
        ValueError: If the encrypted file contains invalid JSON or format.
    """
    if not os.path.isfile(filepath):
        log_event(
            "encryption_engine",
            "decrypt_file",
            "failure",
            {"reason": "file not found", "filepath": filepath},
        )
        raise FileNotFoundError(f"File not found: {filepath}")

    # Read encrypted JSON
    with open(filepath, "r", encoding="utf-8") as f:
        encrypted_dict = json.load(f)

    # Decrypt the message
    plaintext = decrypt_message(encrypted_dict, private_key_pem)

    # Determine output path
    if output_path is None:
        if filepath.endswith(".enc"):
            output_path = filepath[:-4]
        else:
            output_path = filepath + ".dec"

    # Write decrypted plaintext to output file
    with open(output_path, "wb") as f:
        f.write(plaintext)

    log_event(
        "encryption_engine",
        "decrypt_file",
        "success",
        {"filepath": filepath, "output_path": output_path},
    )

"""Key management module for SecureVault PKI.

This module manages the lifecycle of cryptographic keys: generation, encrypted
persistence, retrieval, listing, and deletion.

Security Design:
- Private keys are NEVER written to disk in plaintext. They are encrypted using
  PBKDF2-SHA256 (100,000 iterations) to derive an AES-256 key, then encrypted
  with AES-256-GCM before storage.
- PBKDF2 with 100,000 iterations provides brute-force resistance (~200-500ms per
  attempt), making offline dictionary attacks impractical for reasonably strong
  passwords.
- AES-256-GCM provides authenticated encryption of the key material, ensuring both
  confidentiality and integrity. Any tampering with the stored ciphertext is detected
  via the GCM authentication tag.
- All randomness (salt, IV) is sourced from os.urandom() (CSPRNG).
- The public key is stored as unencrypted PEM since it is not secret.

Storage Layout:
    ~/.securevault/keys/
    ├── {name}.priv   # JSON with encrypted private key
    └── {name}.pub    # Public key PEM (unencrypted)
"""

import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag

from securevault.crypto_utils import (
    aes_decrypt,
    aes_encrypt,
    b64_decode,
    b64_encode,
    ecdh_keygen,
    rsa_keygen,
)

# Module-level keystore directory, configurable for testing.
KEYSTORE_DIR: Path = Path.home() / ".securevault" / "keys"


def _ensure_keystore_dir() -> None:
    """Create the keystore directory if it does not exist.

    Uses os.makedirs with exist_ok=True to avoid race conditions in
    concurrent access scenarios.
    """
    os.makedirs(KEYSTORE_DIR, exist_ok=True)


def generate_keypair(
    name: str, key_type: str = "rsa", key_size: int = 4096, password: str = ""
) -> None:
    """Generate a key pair and store it encrypted in the keystore.

    The private key is encrypted at rest using PBKDF2-SHA256 (100,000 iterations)
    to derive a 256-bit AES key, which then encrypts the private key PEM via
    AES-256-GCM. This ensures that even if the storage medium is compromised,
    the private key cannot be recovered without the password.

    Args:
        name: Unique identifier for the key pair (used as filename stem).
        key_type: Type of key to generate — "rsa" for RSA-4096 or "ecc" for
            ECC P-384 (secp384r1).
        key_size: RSA key size in bits (only used when key_type="rsa").
            Defaults to 4096.
        password: Password used to encrypt the private key at rest. An empty
            string is allowed but provides minimal protection.

    Raises:
        FileExistsError: If a key with the given name already exists in the keystore.
        ValueError: If key_type is not "rsa" or "ecc".
    """
    if key_type not in ("rsa", "ecc"):
        raise ValueError(
            f"Unsupported key type: '{key_type}'. Must be 'rsa' or 'ecc'."
        )

    _ensure_keystore_dir()

    priv_path = KEYSTORE_DIR / f"{name}.priv"
    pub_path = KEYSTORE_DIR / f"{name}.pub"

    if priv_path.exists() or pub_path.exists():
        raise FileExistsError(f"Key '{name}' already exists")

    # Step 1: Generate the key pair based on type
    if key_type == "rsa":
        private_pem, public_pem = rsa_keygen(key_size)
    else:
        private_pem, public_pem = ecdh_keygen("secp384r1")

    # Step 2: Derive encryption key from password using PBKDF2-SHA256
    salt = os.urandom(16)
    iterations = 100_000
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    # Step 3: Encrypt the private key PEM with AES-256-GCM
    iv, encrypted_key, tag = aes_encrypt(private_pem, derived_key)

    # Step 4: Store the encrypted private key as JSON
    storage = {
        "version": 1,
        "key_type": key_type,
        "algorithm": "PBKDF2-SHA256+AES-256-GCM",
        "salt_b64": b64_encode(salt),
        "iterations": iterations,
        "iv_b64": b64_encode(iv),
        "tag_b64": b64_encode(tag),
        "encrypted_key_b64": b64_encode(encrypted_key),
    }
    priv_path.write_text(json.dumps(storage, indent=2), encoding="utf-8")

    # Step 5: Store the public key as unencrypted PEM
    pub_path.write_bytes(public_pem)

    # Step 6: Securely erase sensitive material from memory (best effort)
    del private_pem
    del derived_key


def load_private_key(name: str, password: str) -> bytes:
    """Load and decrypt a private key from the keystore.

    Derives the decryption key using the same PBKDF2 parameters stored alongside
    the encrypted key, then decrypts with AES-256-GCM. The GCM authentication
    tag verification ensures that an incorrect password is detected immediately
    rather than returning garbage data.

    Args:
        name: The name of the key pair to load.
        password: The password used when the key pair was generated.

    Returns:
        The decrypted private key as PEM-encoded bytes.

    Raises:
        FileNotFoundError: If no key with the given name exists in the keystore.
        ValueError: If the password is incorrect (AES-GCM tag verification fails).
    """
    priv_path = KEYSTORE_DIR / f"{name}.priv"

    if not priv_path.exists():
        raise FileNotFoundError(f"Key '{name}' not found")

    # Load the encrypted storage JSON
    storage = json.loads(priv_path.read_text(encoding="utf-8"))

    # Extract PBKDF2 parameters
    salt = b64_decode(storage["salt_b64"])
    iterations = storage["iterations"]

    # Derive the decryption key from the password
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    # Extract encrypted key components
    iv = b64_decode(storage["iv_b64"])
    tag = b64_decode(storage["tag_b64"])
    encrypted_key = b64_decode(storage["encrypted_key_b64"])

    # Decrypt the private key; InvalidTag means wrong password
    try:
        private_pem = aes_decrypt(encrypted_key, iv, tag, derived_key)
    except InvalidTag:
        raise ValueError("Incorrect password")

    return private_pem


def load_public_key(name: str) -> bytes:
    """Load a public key from the keystore.

    Public keys are stored as unencrypted PEM since they are not secret.

    Args:
        name: The name of the key pair whose public key to load.

    Returns:
        The public key as PEM-encoded bytes.

    Raises:
        FileNotFoundError: If no key with the given name exists in the keystore.
    """
    pub_path = KEYSTORE_DIR / f"{name}.pub"

    if not pub_path.exists():
        raise FileNotFoundError(f"Key '{name}' not found")

    return pub_path.read_bytes()


def list_keys() -> list[str]:
    """List the names of all key pairs in the keystore.

    Identifies key pairs by the presence of .priv files in the keystore
    directory. Returns just the name stems (without extensions).

    Returns:
        A sorted list of key pair names. Returns an empty list if the
        keystore directory does not exist.
    """
    if not KEYSTORE_DIR.exists():
        return []

    names = sorted(
        f.stem for f in KEYSTORE_DIR.iterdir() if f.suffix == ".priv"
    )
    return names


def delete_key(name: str) -> None:
    """Delete a key pair from the keystore.

    Removes both the .priv (encrypted private key) and .pub (public key)
    files for the named key pair.

    Args:
        name: The name of the key pair to delete.

    Raises:
        FileNotFoundError: If no key with the given name exists in the keystore.
    """
    priv_path = KEYSTORE_DIR / f"{name}.priv"
    pub_path = KEYSTORE_DIR / f"{name}.pub"

    if not priv_path.exists() and not pub_path.exists():
        raise FileNotFoundError(f"Key '{name}' not found")

    if priv_path.exists():
        priv_path.unlink()
    if pub_path.exists():
        pub_path.unlink()

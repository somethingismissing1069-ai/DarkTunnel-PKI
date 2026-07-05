"""Certificate Authority module for SecureVault PKI.

This module implements Certificate Authority functionality including initialization,
certificate issuance, Certificate Revocation List (CRL) management, and certificate
verification against the CA.

Security Design:
- The CA private key is encrypted at rest using the same PBKDF2-SHA256 + AES-256-GCM
  scheme as key_manager, ensuring consistent protection for all private keys.
- CA operations that require the private key (issuance, revocation verification)
  demand a password on every call, preventing unauthorized operations even if the
  process is compromised.
- Serial numbers are monotonically increasing, starting at 1000, ensuring unique
  certificate identification.
- The CRL is persisted to disk on every revocation, ensuring durability across restarts.

CA Directory Layout:
    ~/.securevault/ca/
    ├── ca_cert.json    # Self-signed CA certificate (JSON)
    ├── ca_key.enc      # Encrypted CA private key (same format as key_manager)
    ├── crl.json        # Certificate Revocation List {"serials": [1001, 1002, ...]}
    └── serial.json     # Serial counter {"next_serial": 1001}
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidTag

from securevault.crypto_utils import (
    aes_decrypt,
    aes_encrypt,
    b64_decode,
    b64_encode,
    rsa_keygen,
)
from securevault.logging_utils import log_event
from securevault.pki_utils import (
    create_cert,
    sign_certificate,
    verify_certificate,
)

# Module-level CA directory, configurable for testing.
CA_DIR: Path = Path.home() / ".securevault" / "ca"


def _ensure_ca_dir() -> None:
    """Create the CA directory if it does not exist.

    Uses os.makedirs with exist_ok=True to avoid race conditions in
    concurrent access scenarios.
    """
    os.makedirs(CA_DIR, exist_ok=True)


def _encrypt_private_key(private_key_pem: bytes, password: str) -> dict:
    """Encrypt a private key using PBKDF2-SHA256 + AES-256-GCM.

    Uses the same encryption format as key_manager for consistency across
    the SecureVault system. PBKDF2 with 100,000 iterations provides
    brute-force resistance.

    Args:
        private_key_pem: The PEM-encoded private key bytes to encrypt.
        password: The password used to derive the encryption key.

    Returns:
        A dictionary containing all fields needed to decrypt the key later.
    """
    salt = os.urandom(16)
    iterations = 100_000
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    iv, encrypted_key, tag = aes_encrypt(private_key_pem, derived_key)

    storage = {
        "version": 1,
        "key_type": "rsa",
        "algorithm": "PBKDF2-SHA256+AES-256-GCM",
        "salt_b64": b64_encode(salt),
        "iterations": iterations,
        "iv_b64": b64_encode(iv),
        "tag_b64": b64_encode(tag),
        "encrypted_key_b64": b64_encode(encrypted_key),
    }

    return storage


def _decrypt_private_key(storage: dict, password: str) -> bytes:
    """Decrypt a private key from the encrypted storage format.

    Derives the decryption key using the same PBKDF2 parameters stored
    alongside the encrypted key, then decrypts with AES-256-GCM.

    Args:
        storage: The encrypted key storage dictionary.
        password: The password used when the key was encrypted.

    Returns:
        The decrypted private key as PEM-encoded bytes.

    Raises:
        ValueError: If the password is incorrect (AES-GCM tag verification fails).
    """
    salt = b64_decode(storage["salt_b64"])
    iterations = storage["iterations"]

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    iv = b64_decode(storage["iv_b64"])
    tag = b64_decode(storage["tag_b64"])
    encrypted_key = b64_decode(storage["encrypted_key_b64"])

    try:
        private_pem = aes_decrypt(encrypted_key, iv, tag, derived_key)
    except InvalidTag:
        raise ValueError("Incorrect password")

    return private_pem


def _load_ca_private_key(password: str) -> bytes:
    """Load and decrypt the CA private key.

    Args:
        password: The CA password.

    Returns:
        The CA private key as PEM-encoded bytes.

    Raises:
        RuntimeError: If CA is not initialized.
        ValueError: If password is incorrect.
    """
    key_path = CA_DIR / "ca_key.enc"

    if not key_path.exists():
        raise RuntimeError("CA not initialized. Call init_ca() first.")

    storage = json.loads(key_path.read_text(encoding="utf-8"))
    return _decrypt_private_key(storage, password)


def _load_serial() -> dict:
    """Load the serial counter from disk.

    Returns:
        The serial counter dictionary with 'next_serial' field.

    Raises:
        RuntimeError: If CA is not initialized.
    """
    serial_path = CA_DIR / "serial.json"

    if not serial_path.exists():
        raise RuntimeError("CA not initialized. Call init_ca() first.")

    return json.loads(serial_path.read_text(encoding="utf-8"))


def _save_serial(serial_data: dict) -> None:
    """Persist the serial counter to disk.

    Args:
        serial_data: The serial counter dictionary with 'next_serial' field.
    """
    serial_path = CA_DIR / "serial.json"
    serial_path.write_text(json.dumps(serial_data, indent=2), encoding="utf-8")


def _load_crl() -> set:
    """Load the CRL from disk.

    Returns:
        A set of revoked serial numbers.

    Raises:
        RuntimeError: If CA is not initialized.
    """
    crl_path = CA_DIR / "crl.json"

    if not crl_path.exists():
        raise RuntimeError("CA not initialized. Call init_ca() first.")

    data = json.loads(crl_path.read_text(encoding="utf-8"))
    return set(data.get("serials", []))


def _save_crl(serials: set) -> None:
    """Persist the CRL to disk.

    Args:
        serials: The set of revoked serial numbers to persist.
    """
    crl_path = CA_DIR / "crl.json"
    data = {"serials": sorted(serials)}
    crl_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def init_ca(ca_name: str = "SecureVault CA", password: str = "") -> None:
    """Initialize the Certificate Authority.

    Generates a CA RSA-4096 key pair, creates a self-signed CA certificate,
    initializes an empty Certificate Revocation List, and creates a serial
    counter starting at 1000. The CA private key is encrypted with the
    provided password using PBKDF2-SHA256 + AES-256-GCM.

    Args:
        ca_name: The name for the Certificate Authority. Used as both
            subject and issuer in the self-signed certificate.
        password: Password used to encrypt the CA private key at rest.
            An empty string is allowed but provides minimal protection.

    Raises:
        FileExistsError: If the CA has already been initialized (ca_cert.json exists).
    """
    _ensure_ca_dir()

    cert_path = CA_DIR / "ca_cert.json"
    if cert_path.exists():
        raise FileExistsError("CA already initialized")

    # Step 1: Generate RSA-4096 key pair
    private_pem, public_pem = rsa_keygen(4096)

    # Step 2: Encrypt and store the CA private key
    key_storage = _encrypt_private_key(private_pem, password)
    key_path = CA_DIR / "ca_key.enc"
    key_path.write_text(json.dumps(key_storage, indent=2), encoding="utf-8")

    # Step 3: Create self-signed CA certificate (serial=1, validity=3650 days)
    ca_cert = create_cert(
        subject=ca_name,
        public_key_pem=public_pem,
        issuer=ca_name,
        serial=1,
        validity_days=3650,
    )

    # Step 4: Sign the certificate with the CA's own private key
    signed_ca_cert = sign_certificate(ca_cert, private_pem)

    # Step 5: Store the CA certificate
    cert_path.write_text(json.dumps(signed_ca_cert, indent=2), encoding="utf-8")

    # Step 6: Initialize empty CRL
    _save_crl(set())

    # Step 7: Initialize serial counter at 1000
    _save_serial({"next_serial": 1000})

    # Step 8: Securely erase private key from memory (best effort)
    del private_pem

    log_event(
        "certificate_authority",
        "init_ca",
        "success",
        {"ca_name": ca_name},
    )


def issue_certificate(
    subject: str, public_key_pem: bytes, validity_days: int = 365, password: str = ""
) -> dict:
    """Issue a new certificate signed by the CA.

    Verifies the CA password, creates an unsigned certificate with the next
    available serial number, signs it with the CA private key, increments
    the serial counter, and persists the updated counter.

    Args:
        subject: The identity to bind to the public key (e.g., "Alice Smith").
        public_key_pem: PEM-encoded public key bytes for the certificate subject.
        validity_days: Number of days the certificate is valid (1-3650).
        password: The CA password to decrypt the CA private key.

    Returns:
        A signed certificate dictionary containing all certificate fields
        including the CA's RSA-PSS signature.

    Raises:
        RuntimeError: If the CA has not been initialized.
        ValueError: If the CA password is incorrect.
    """
    # Verify CA is initialized
    cert_path = CA_DIR / "ca_cert.json"
    if not cert_path.exists():
        raise RuntimeError("CA not initialized. Call init_ca() first.")

    # Verify CA password by loading the private key
    ca_private_key = _load_ca_private_key(password)

    # Load CA certificate to get issuer name
    ca_cert = json.loads(cert_path.read_text(encoding="utf-8"))
    issuer = ca_cert["issuer"]

    # Get and increment serial
    serial_data = _load_serial()
    serial = serial_data["next_serial"]
    serial_data["next_serial"] = serial + 1
    _save_serial(serial_data)

    # Create unsigned certificate
    cert = create_cert(
        subject=subject,
        public_key_pem=public_key_pem,
        issuer=issuer,
        serial=serial,
        validity_days=validity_days,
    )

    # Sign with CA private key
    signed_cert = sign_certificate(cert, ca_private_key)

    # Securely erase private key from memory (best effort)
    del ca_private_key

    log_event(
        "certificate_authority",
        "issue_certificate",
        "success",
        {"subject": subject, "serial": serial},
    )

    return signed_cert


def revoke_certificate(serial: int, password: str = "") -> None:
    """Revoke a certificate by adding its serial number to the CRL.

    Verifies the CA password, adds the specified serial number to the
    Certificate Revocation List, and persists the updated CRL to disk.

    Args:
        serial: The serial number of the certificate to revoke.
        password: The CA password to verify authorization.

    Raises:
        RuntimeError: If the CA has not been initialized.
        ValueError: If the CA password is incorrect.
    """
    # Verify CA is initialized
    cert_path = CA_DIR / "ca_cert.json"
    if not cert_path.exists():
        raise RuntimeError("CA not initialized. Call init_ca() first.")

    # Verify CA password
    _load_ca_private_key(password)

    # Load current CRL
    crl = _load_crl()

    # Add serial to CRL
    crl.add(serial)

    # Persist updated CRL
    _save_crl(crl)

    log_event(
        "certificate_authority",
        "revoke_certificate",
        "success",
        {"serial": serial},
    )


def get_ca_certificate() -> dict:
    """Load and return the CA's self-signed certificate.

    Returns:
        The CA certificate as a dictionary containing all certificate fields
        including subject, public_key, issuer, serial, timestamps, and signature.

    Raises:
        RuntimeError: If the CA has not been initialized.
    """
    cert_path = CA_DIR / "ca_cert.json"

    if not cert_path.exists():
        raise RuntimeError("CA not initialized. Call init_ca() first.")

    return json.loads(cert_path.read_text(encoding="utf-8"))


def get_crl() -> set:
    """Load and return the current Certificate Revocation List.

    Returns:
        A set of integers representing the serial numbers of all revoked
        certificates.

    Raises:
        RuntimeError: If the CA has not been initialized.
    """
    return _load_crl()


def verify_issued_cert(cert: dict, password: str = "") -> Tuple[bool, str]:
    """Verify that a certificate was issued by this CA.

    Loads the CA public key from the CA certificate and the current CRL,
    then delegates to pki_utils.verify_certificate for full validation
    (temporal validity, revocation status, signature verification).

    Args:
        cert: The certificate dictionary to verify.
        password: The CA password (not currently used for verification
            since only the public key is needed, but included for API
            consistency).

    Returns:
        A tuple of (is_valid, reason):
        - (True, "valid") if all checks pass
        - (False, "expired") if the certificate has expired
        - (False, "not_yet_valid") if the certificate is not yet valid
        - (False, "revoked") if the certificate serial is in the CRL
        - (False, "bad_signature") if signature verification fails
    """
    # Load CA certificate to get public key
    ca_cert = get_ca_certificate()
    ca_public_key_pem = ca_cert["public_key"].encode("utf-8")

    # Load current CRL
    crl = _load_crl()

    # Verify using pki_utils
    return verify_certificate(cert, ca_public_key_pem, crl)

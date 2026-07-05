"""PKI utilities for SecureVault — Certificate Structures & Validation.

This module manages JSON-based certificate structures, canonical serialization,
certificate signing, and chain validation. It builds on crypto_utils for all
cryptographic operations and provides the certificate abstraction layer used
by higher-level modules (certificate_authority, signature_engine).

Security Design:
- Canonical JSON ensures deterministic signing/verification (no serialization ambiguity).
- Validation order (temporal → revocation → signature) prevents timing leaks about
  signature validity of expired/revoked certs and avoids expensive signature checks
  when simpler checks can reject early.
- All PEM key loading is centralized here to provide a single audit point for key parsing.
"""

import json
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization

from securevault.crypto_utils import b64_decode, b64_encode, rsa_sign, rsa_verify


@dataclass
class CertificateInfo:
    """Represents a parsed certificate with all standard fields.

    This dataclass provides a typed view of a certificate dictionary,
    useful for code that prefers attribute access over dict key access.

    Attributes:
        subject: The entity this certificate identifies (e.g., "Alice Smith").
        public_key: PEM-encoded public key as a string.
        issuer: The CA or entity that issued this certificate.
        serial: Positive integer uniquely identifying this certificate.
        not_before: Unix timestamp marking the start of the validity period.
        not_after: Unix timestamp marking the end of the validity period.
        signature: Base64-encoded RSA-PSS signature from the issuing CA.
    """

    subject: str
    public_key: str
    issuer: str
    serial: int
    not_before: float
    not_after: float
    signature: str


def canonical_json(obj: dict) -> str:
    """Produce deterministic JSON serialization for cryptographic signing.

    Deterministic serialization is critical for digital signatures: the signer
    and verifier must compute the exact same byte sequence from the same logical
    data structure. This function guarantees:
    - Lexicographically sorted keys at ALL nesting levels
    - Compact separators (no whitespace between tokens)
    - ASCII-safe encoding (non-ASCII chars escaped as \\uXXXX)

    These properties ensure that canonical_json(obj) == canonical_json(obj) always,
    regardless of Python dict insertion order or platform differences.

    Args:
        obj: A JSON-serializable dictionary. All values must be primitive types
             (str, int, float, bool, None) or nested dicts/lists thereof.

    Returns:
        A deterministic JSON string suitable for signing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def create_cert(
    subject: str,
    public_key_pem: bytes,
    issuer: str,
    serial: int,
    validity_days: int,
) -> dict:
    """Create an unsigned certificate dictionary.

    Constructs a certificate with all required fields, computing not_before
    (current time) and not_after (current time + validity_days). The certificate
    is returned without a signature — use sign_certificate() to add the CA signature.

    The key_type field is inferred from the PEM content to allow downstream
    consumers to quickly determine the algorithm without parsing the key.

    Args:
        subject: Identity bound to the public key. Must be non-empty, max 256 chars.
        public_key_pem: PEM-encoded public key bytes (RSA or ECC).
        issuer: Name of the issuing CA (e.g., "SecureVault CA").
        serial: Positive integer uniquely identifying this certificate.
        validity_days: Number of days the certificate is valid (1-3650).

    Returns:
        A certificate dictionary with all fields populated except signature
        (set to empty string).

    Raises:
        ValueError: If subject is empty or exceeds 256 chars, serial is not
                    positive, or validity_days is outside 1-3650 range.
    """
    # Validate subject
    if not subject or not subject.strip():
        raise ValueError("Subject must be a non-empty string")
    if len(subject) > 256:
        raise ValueError("Subject must be at most 256 characters")

    # Validate serial
    if not isinstance(serial, int) or serial <= 0:
        raise ValueError("Serial must be a positive integer")

    # Validate validity_days
    if not isinstance(validity_days, int) or validity_days < 1 or validity_days > 3650:
        raise ValueError("Validity must be between 1 and 3650 days")

    # Compute temporal bounds
    now = time.time()
    not_before = now
    not_after = now + (validity_days * 86400)  # 86400 seconds per day

    # Determine key type from PEM content
    public_key_str = public_key_pem.decode("utf-8") if isinstance(public_key_pem, bytes) else public_key_pem
    key_type = _detect_key_type(public_key_pem)

    return {
        "subject": subject,
        "public_key": public_key_str,
        "issuer": issuer,
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
        "key_type": key_type,
        "signature": "",
    }


def sign_certificate(cert_dict: dict, ca_private_key_pem: bytes) -> dict:
    """Sign a certificate with the CA's private key using RSA-PSS.

    The signing process:
    1. Remove the 'signature' field from the certificate dict.
    2. Compute canonical_json of the remaining fields.
    3. Sign the canonical JSON bytes with RSA-PSS (via crypto_utils.rsa_sign).
    4. Store the base64-encoded signature back in the certificate.

    This ensures that any modification to any certificate field will invalidate
    the signature, providing integrity and authenticity guarantees.

    Args:
        cert_dict: Certificate dictionary (may have empty or missing signature).
        ca_private_key_pem: PEM-encoded RSA private key of the CA.

    Returns:
        A new certificate dictionary with the 'signature' field populated
        with the base64-encoded RSA-PSS signature.
    """
    # Create a copy without the signature field for signing
    cert_without_sig = {k: v for k, v in cert_dict.items() if k != "signature"}

    # Compute the content to be signed
    signed_content = canonical_json(cert_without_sig).encode("utf-8")

    # Sign using RSA-PSS via crypto_utils
    signature_b64 = rsa_sign(signed_content, ca_private_key_pem)

    # Return a new dict with signature populated
    signed_cert = dict(cert_dict)
    signed_cert["signature"] = signature_b64

    return signed_cert


def verify_certificate(
    cert: dict,
    ca_public_key_pem: bytes,
    crl: Optional[set] = None,
) -> Tuple[bool, str]:
    """Validate a certificate against the CA public key and optional CRL.

    Validation is performed in a strict order to avoid leaking information
    about later checks when earlier checks fail, and to avoid expensive
    signature verification when simpler checks can reject:

    1. Temporal validity: Is the certificate within its validity period?
    2. Revocation status: Is the serial number in the CRL?
    3. Signature verification: Does the CA signature match?

    This ordering also provides performance benefits by rejecting expired
    or revoked certificates without performing RSA signature verification.

    Args:
        cert: Certificate dictionary to validate.
        ca_public_key_pem: PEM-encoded RSA public key of the issuing CA.
        crl: Optional set of revoked serial numbers (integers).
             If None, revocation check is skipped.

    Returns:
        A tuple of (is_valid, reason):
        - (True, "valid") if all checks pass
        - (False, "expired") if not_after < current time
        - (False, "not_yet_valid") if not_before > current time
        - (False, "revoked") if serial is in the CRL
        - (False, "bad_signature") if signature verification fails
    """
    current_time = time.time()

    # Step 1: Check temporal validity
    if current_time > cert["not_after"]:
        return (False, "expired")

    if current_time < cert["not_before"]:
        return (False, "not_yet_valid")

    # Step 2: Check revocation status
    if crl is not None and cert["serial"] in crl:
        return (False, "revoked")

    # Step 3: Verify CA signature
    cert_without_sig = {k: v for k, v in cert.items() if k != "signature"}
    signed_content = canonical_json(cert_without_sig).encode("utf-8")

    is_sig_valid = rsa_verify(signed_content, cert["signature"], ca_public_key_pem)

    if not is_sig_valid:
        return (False, "bad_signature")

    return (True, "valid")


def serialize_cert_to_json(cert: dict) -> str:
    """Serialize a certificate dictionary to a JSON string for storage/transmission.

    Unlike canonical_json, this uses human-readable formatting (indentation)
    suitable for storage and debugging. The output can be deserialized back
    to the original dictionary using deserialize_cert_from_json.

    Args:
        cert: Certificate dictionary to serialize.

    Returns:
        A JSON string representation of the certificate.
    """
    return json.dumps(cert, indent=2)


def deserialize_cert_from_json(cert_json: str) -> dict:
    """Deserialize a JSON string back to a certificate dictionary.

    Parses the JSON string produced by serialize_cert_to_json (or any valid
    JSON certificate representation) back into a Python dictionary.

    Args:
        cert_json: JSON string representing a certificate.

    Returns:
        The certificate as a Python dictionary.

    Raises:
        json.JSONDecodeError: If the input is not valid JSON.
    """
    return json.loads(cert_json)


def load_pem_public_key(pem: bytes) -> object:
    """Load a public key from PEM-encoded bytes.

    Centralizes public key loading to provide a single audit point for
    key parsing. Supports both RSA and ECC public keys.

    Args:
        pem: PEM-encoded public key bytes.

    Returns:
        A public key object from the cryptography library (either
        RSAPublicKey or EllipticCurvePublicKey).

    Raises:
        ValueError: If the PEM data is malformed or not a valid public key.
    """
    try:
        return serialization.load_pem_public_key(pem)
    except Exception as e:
        raise ValueError(f"Failed to load public key: {e}") from e


def load_pem_private_key(pem: bytes, password: Optional[bytes] = None) -> object:
    """Load a private key from PEM-encoded bytes, optionally decrypting.

    Centralizes private key loading to provide a single audit point.
    Supports both RSA and ECC private keys, with optional password-based
    decryption for encrypted PEM files.

    Args:
        pem: PEM-encoded private key bytes.
        password: Optional password bytes for decrypting encrypted PEM keys.
                  Pass None for unencrypted keys.

    Returns:
        A private key object from the cryptography library (either
        RSAPrivateKey or EllipticCurvePrivateKey).

    Raises:
        ValueError: If the PEM data is malformed, the password is incorrect,
                    or the key cannot be loaded.
    """
    try:
        return serialization.load_pem_private_key(pem, password=password)
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}") from e


def _detect_key_type(public_key_pem: bytes) -> str:
    """Detect whether a PEM-encoded public key is RSA or ECC.

    Inspects the loaded key object type to determine the key algorithm.
    This avoids fragile string matching on PEM headers.

    Args:
        public_key_pem: PEM-encoded public key bytes.

    Returns:
        "rsa" for RSA keys, "ecc" for Elliptic Curve keys.

    Raises:
        ValueError: If the key type cannot be determined.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, rsa as rsa_module

    key = load_pem_public_key(public_key_pem)

    if isinstance(key, rsa_module.RSAPublicKey):
        return "rsa"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        return "ecc"
    else:
        raise ValueError(f"Unsupported key type: {type(key)}")

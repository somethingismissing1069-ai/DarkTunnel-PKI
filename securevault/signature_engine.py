"""Digital Signature Engine for SecureVault PKI.

This module orchestrates file and message signing/verification workflows
using RSA-PSS signatures with SHA-256 hashing. It provides detached digital
signatures that bind document content to a signer's identity through the
PKI certificate chain.

Security Design:
- Signatures are detached: the original file/message is never modified.
- Verification always validates the certificate chain BEFORE checking the
  data signature, ensuring revoked/expired signers are rejected early without
  leaking information about the signature itself.
- SHA-256 is used via hashlib (not the cryptography library) for hashing file
  contents, as the RSA-PSS signature via crypto_utils handles its own internal
  hash for the signing operation. The signed payload is the raw 32-byte SHA-256
  digest of the file/message contents.
- All signing and verification events are logged via logging_utils for
  audit trail and incident investigation purposes.
- Timestamps are captured at signing time to support non-repudiation claims
  (proving that the signature existed at a certain point in time).
"""

import hashlib
import json
import os
import time
from typing import Optional, Tuple

from securevault.crypto_utils import b64_decode, b64_encode, rsa_sign, rsa_verify
from securevault.logging_utils import log_event
from securevault.pki_utils import verify_certificate


def sign_file(filepath: str, private_key_pem: bytes, signer_cert: dict) -> bytes:
    """Create a detached digital signature for a file.

    Reads the file contents, computes a SHA-256 hash, signs the hash with
    RSA-PSS, and packages the signature along with metadata into a JSON
    structure. The original file is never modified.

    The signature format includes the signer's certificate, enabling verifiers
    to validate the certificate chain and establish the signer's identity
    without requiring out-of-band certificate distribution.

    Args:
        filepath: Path to the file to sign. Must exist and be readable.
        private_key_pem: PEM-encoded RSA private key of the signer.
        signer_cert: Certificate dictionary of the signer, included in the
                     signature for chain validation during verification.

    Returns:
        JSON-encoded signature bytes (UTF-8) containing the detached signature,
        signer certificate, timestamp, algorithm identifier, and filename.

    Raises:
        FileNotFoundError: If the specified file does not exist.
    """
    # Validate file existence
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    # Read file contents (do NOT modify the original file)
    with open(filepath, "rb") as f:
        file_contents = f.read()

    # Compute SHA-256 hash of the file contents
    file_hash = hashlib.sha256(file_contents).digest()

    # Sign the raw 32-byte SHA-256 hash with RSA-PSS
    signature_b64 = rsa_sign(file_hash, private_key_pem)

    # Package as JSON signature structure
    signature_payload = {
        "version": 1,
        "algorithm": "RSA-PSS-SHA256",
        "signature": signature_b64,
        "signer_cert": signer_cert,
        "timestamp": time.time(),
        "filename": os.path.basename(filepath),
    }

    # Encode to UTF-8 JSON bytes
    signature_bytes = json.dumps(signature_payload, ensure_ascii=True).encode("utf-8")

    # Log the signing event
    log_event(
        component="signature_engine",
        event="sign_file",
        result="success",
        details={
            "filename": os.path.basename(filepath),
            "subject": signer_cert.get("subject", "unknown"),
        },
    )

    return signature_bytes


def sign_message(message: bytes, private_key_pem: bytes, signer_cert: dict) -> bytes:
    """Create a detached digital signature for an in-memory message.

    Functionally identical to sign_file but operates on message bytes directly
    instead of reading from the filesystem. The filename field is omitted
    (set to empty string) since there is no associated file.

    This is useful for signing protocol messages, API payloads, or any data
    that exists only in memory without a filesystem representation.

    Args:
        message: The message bytes to sign.
        private_key_pem: PEM-encoded RSA private key of the signer.
        signer_cert: Certificate dictionary of the signer.

    Returns:
        JSON-encoded signature bytes (UTF-8) containing the detached signature,
        signer certificate, timestamp, and algorithm identifier.
    """
    # Compute SHA-256 hash of the message
    message_hash = hashlib.sha256(message).digest()

    # Sign the raw 32-byte SHA-256 hash with RSA-PSS
    signature_b64 = rsa_sign(message_hash, private_key_pem)

    # Package as JSON signature structure (no filename for messages)
    signature_payload = {
        "version": 1,
        "algorithm": "RSA-PSS-SHA256",
        "signature": signature_b64,
        "signer_cert": signer_cert,
        "timestamp": time.time(),
        "filename": "",
    }

    # Encode to UTF-8 JSON bytes
    signature_bytes = json.dumps(signature_payload, ensure_ascii=True).encode("utf-8")

    # Log the signing event
    log_event(
        component="signature_engine",
        event="sign_message",
        result="success",
        details={
            "subject": signer_cert.get("subject", "unknown"),
        },
    )

    return signature_bytes


def verify_file_signature(
    filepath: str,
    signature: bytes,
    signer_cert: dict,
    ca_cert: dict,
    crl: Optional[set] = None,
) -> Tuple[bool, str]:
    """Verify a detached digital signature against a file.

    Verification is performed in a strict order to prevent information leakage
    and ensure security guarantees:
    1. Validate the signer's certificate chain (temporal, revocation, CA signature).
    2. Only if the certificate is valid, proceed to verify the file signature.

    This ordering ensures that signatures from revoked or expired certificates
    are rejected without revealing whether the file signature itself is valid,
    preventing potential oracle attacks.

    Args:
        filepath: Path to the file whose signature is being verified.
        signature: JSON-encoded signature bytes (as produced by sign_file).
        signer_cert: Certificate dictionary of the claimed signer.
        ca_cert: Certificate dictionary of the Certificate Authority.
        crl: Optional set of revoked certificate serial numbers.

    Returns:
        A tuple of (is_valid, reason):
        - (True, "valid") if certificate chain and file signature are both valid
        - (False, "expired") if the signer certificate has expired
        - (False, "revoked") if the signer certificate is revoked
        - (False, "untrusted_issuer") if the CA signature on the cert is invalid
        - (False, "not_yet_valid") if the signer cert is not yet valid
        - (False, "bad_signature") if the file signature does not match

    Raises:
        FileNotFoundError: If the specified file does not exist.
    """
    # Validate file existence
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    # Step 1: Validate the signer's certificate chain
    ca_public_key_pem = ca_cert["public_key"].encode("utf-8")
    cert_valid, cert_reason = verify_certificate(signer_cert, ca_public_key_pem, crl)

    if not cert_valid:
        # Map pki_utils reasons to signature_engine reasons
        reason = _map_cert_failure_reason(cert_reason)

        log_event(
            component="signature_engine",
            event="verify_file_signature",
            result="failure",
            details={
                "filename": os.path.basename(filepath),
                "reason": reason,
                "subject": signer_cert.get("subject", "unknown"),
            },
        )

        return (False, reason)

    # Step 2: Read file and compute SHA-256 hash
    with open(filepath, "rb") as f:
        file_contents = f.read()

    file_hash = hashlib.sha256(file_contents).digest()

    # Step 3: Extract signature from the JSON signature blob
    sig_data = json.loads(signature)
    signature_b64 = sig_data["signature"]

    # Step 4: Verify RSA-PSS signature using signer's public key
    signer_public_key_pem = signer_cert["public_key"].encode("utf-8")
    is_sig_valid = rsa_verify(file_hash, signature_b64, signer_public_key_pem)

    if is_sig_valid:
        log_event(
            component="signature_engine",
            event="verify_file_signature",
            result="success",
            details={
                "filename": os.path.basename(filepath),
                "subject": signer_cert.get("subject", "unknown"),
            },
        )
        return (True, "valid")
    else:
        log_event(
            component="signature_engine",
            event="verify_file_signature",
            result="failure",
            details={
                "filename": os.path.basename(filepath),
                "reason": "bad_signature",
                "subject": signer_cert.get("subject", "unknown"),
            },
        )
        return (False, "bad_signature")


def verify_message_signature(
    message: bytes,
    signature: bytes,
    signer_cert: dict,
    ca_cert: dict,
    crl: Optional[set] = None,
) -> Tuple[bool, str]:
    """Verify a detached digital signature against an in-memory message.

    Functionally identical to verify_file_signature but operates on message
    bytes directly instead of reading from the filesystem.

    The verification order is the same: certificate chain validation first,
    then signature verification.

    Args:
        message: The original message bytes that were signed.
        signature: JSON-encoded signature bytes (as produced by sign_message).
        signer_cert: Certificate dictionary of the claimed signer.
        ca_cert: Certificate dictionary of the Certificate Authority.
        crl: Optional set of revoked certificate serial numbers.

    Returns:
        A tuple of (is_valid, reason):
        - (True, "valid") if certificate chain and message signature are both valid
        - (False, "expired") if the signer certificate has expired
        - (False, "revoked") if the signer certificate is revoked
        - (False, "untrusted_issuer") if the CA signature on the cert is invalid
        - (False, "not_yet_valid") if the signer cert is not yet valid
        - (False, "bad_signature") if the message signature does not match
    """
    # Step 1: Validate the signer's certificate chain
    ca_public_key_pem = ca_cert["public_key"].encode("utf-8")
    cert_valid, cert_reason = verify_certificate(signer_cert, ca_public_key_pem, crl)

    if not cert_valid:
        # Map pki_utils reasons to signature_engine reasons
        reason = _map_cert_failure_reason(cert_reason)

        log_event(
            component="signature_engine",
            event="verify_message_signature",
            result="failure",
            details={
                "reason": reason,
                "subject": signer_cert.get("subject", "unknown"),
            },
        )

        return (False, reason)

    # Step 2: Compute SHA-256 hash of the message
    message_hash = hashlib.sha256(message).digest()

    # Step 3: Extract signature from the JSON signature blob
    sig_data = json.loads(signature)
    signature_b64 = sig_data["signature"]

    # Step 4: Verify RSA-PSS signature using signer's public key
    signer_public_key_pem = signer_cert["public_key"].encode("utf-8")
    is_sig_valid = rsa_verify(message_hash, signature_b64, signer_public_key_pem)

    if is_sig_valid:
        log_event(
            component="signature_engine",
            event="verify_message_signature",
            result="success",
            details={
                "subject": signer_cert.get("subject", "unknown"),
            },
        )
        return (True, "valid")
    else:
        log_event(
            component="signature_engine",
            event="verify_message_signature",
            result="failure",
            details={
                "reason": "bad_signature",
                "subject": signer_cert.get("subject", "unknown"),
            },
        )
        return (False, "bad_signature")


def _map_cert_failure_reason(pki_reason: str) -> str:
    """Map pki_utils certificate validation failure reasons to signature_engine reasons.

    The mapping translates internal PKI terminology to user-facing signature
    verification terminology:
    - "bad_signature" (PKI) → "untrusted_issuer" (indicates the CA didn't sign this cert)
    - Other reasons pass through unchanged.

    Args:
        pki_reason: The reason string from pki_utils.verify_certificate.

    Returns:
        The mapped reason string for the signature_engine's return value.
    """
    reason_map = {
        "bad_signature": "untrusted_issuer",
        "expired": "expired",
        "revoked": "revoked",
        "not_yet_valid": "not_yet_valid",
    }
    return reason_map.get(pki_reason, pki_reason)

"""Tests for securevault.schema_validation module.

Validates the four schema validation functions against valid inputs,
invalid inputs, and edge cases to ensure proper rejection with clear messages.
"""

import os
import time

import pytest

from securevault.crypto_utils import b64_encode, ecdh_keygen, rsa_keygen
from securevault.schema_validation import (
    validate_certificate,
    validate_encrypted_message,
    validate_key_storage,
    validate_signature_payload,
)


# ============================================================
# Fixtures for valid test data
# ============================================================


@pytest.fixture
def valid_rsa_public_key_pem():
    """Generate a real RSA public key for testing."""
    _, pub = rsa_keygen(2048)  # Use smaller key for speed in tests
    return pub.decode("utf-8")


@pytest.fixture
def valid_ecc_public_key_pem():
    """Generate a real ECC public key for testing."""
    _, pub = ecdh_keygen("secp384r1")
    return pub.decode("utf-8")


@pytest.fixture
def valid_certificate(valid_rsa_public_key_pem):
    """A well-formed certificate dictionary."""
    now = time.time()
    return {
        "subject": "Alice Smith",
        "public_key": valid_rsa_public_key_pem,
        "issuer": "SecureVault CA",
        "serial": 1001,
        "not_before": now - 3600,
        "not_after": now + 86400,
        "key_type": "rsa",
        "signature": b64_encode(b"fake-signature-bytes"),
    }


@pytest.fixture
def valid_signature_payload(valid_certificate):
    """A well-formed detached signature payload."""
    return {
        "version": 1,
        "algorithm": "RSA-PSS-SHA256",
        "signature": b64_encode(b"some-signature-data"),
        "signer_cert": valid_certificate,
        "timestamp": time.time() - 10,
        "filename": "report.pdf",
    }


@pytest.fixture
def valid_encrypted_message(valid_ecc_public_key_pem):
    """A well-formed encrypted message dictionary."""
    return {
        "version": 1,
        "algorithm": "ECDH-P384+HKDF-SHA256+AES-256-GCM",
        "ephemeral_pub_b64": b64_encode(valid_ecc_public_key_pem.encode("utf-8")),
        "iv_b64": b64_encode(os.urandom(12)),
        "tag_b64": b64_encode(os.urandom(16)),
        "ciphertext_b64": b64_encode(b"encrypted-data-here"),
        "nonce_b64": b64_encode(os.urandom(16)),
        "timestamp": time.time(),
    }


@pytest.fixture
def valid_key_storage():
    """A well-formed key storage dictionary."""
    return {
        "version": 1,
        "key_type": "rsa",
        "algorithm": "PBKDF2-SHA256+AES-256-GCM",
        "salt_b64": b64_encode(os.urandom(16)),
        "iterations": 100000,
        "iv_b64": b64_encode(os.urandom(12)),
        "tag_b64": b64_encode(os.urandom(16)),
        "encrypted_key_b64": b64_encode(b"encrypted-private-key-data"),
    }


# ============================================================
# Tests for validate_certificate
# ============================================================


class TestValidateCertificate:
    def test_valid_certificate(self, valid_certificate):
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is True
        assert reason == "valid"

    def test_serial_not_positive(self, valid_certificate):
        valid_certificate["serial"] = 0
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "serial" in reason

    def test_serial_negative(self, valid_certificate):
        valid_certificate["serial"] = -1
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "serial" in reason

    def test_serial_not_int(self, valid_certificate):
        valid_certificate["serial"] = "1001"
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "serial" in reason

    def test_subject_empty(self, valid_certificate):
        valid_certificate["subject"] = ""
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "subject" in reason

    def test_subject_whitespace_only(self, valid_certificate):
        valid_certificate["subject"] = "   "
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "subject" in reason

    def test_subject_too_long(self, valid_certificate):
        valid_certificate["subject"] = "A" * 257
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "subject" in reason

    def test_subject_max_length_valid(self, valid_certificate):
        valid_certificate["subject"] = "A" * 256
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is True

    def test_key_type_invalid(self, valid_certificate):
        valid_certificate["key_type"] = "dsa"
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "key_type" in reason

    def test_key_type_ecc_valid(self, valid_certificate):
        valid_certificate["key_type"] = "ecc"
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is True

    def test_public_key_not_pem(self, valid_certificate):
        valid_certificate["public_key"] = "not-a-pem-key"
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "public_key" in reason

    def test_signature_invalid_base64(self, valid_certificate):
        valid_certificate["signature"] = "not!valid!base64!!!"
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "signature" in reason

    def test_signature_empty_valid(self, valid_certificate):
        valid_certificate["signature"] = ""
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is True

    def test_not_before_after_not_after(self, valid_certificate):
        valid_certificate["not_before"] = time.time() + 1000
        valid_certificate["not_after"] = time.time()
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "not_before" in reason

    def test_not_before_equals_not_after(self, valid_certificate):
        t = time.time()
        valid_certificate["not_before"] = t
        valid_certificate["not_after"] = t
        is_valid, reason = validate_certificate(valid_certificate)
        assert is_valid is False
        assert "not_before" in reason


# ============================================================
# Tests for validate_signature_payload
# ============================================================


class TestValidateSignaturePayload:
    def test_valid_signature_payload(self, valid_signature_payload):
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is True
        assert reason == "valid"

    def test_wrong_version(self, valid_signature_payload):
        valid_signature_payload["version"] = 2
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "version" in reason

    def test_wrong_algorithm(self, valid_signature_payload):
        valid_signature_payload["algorithm"] = "RSA-SHA256"
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "algorithm" in reason

    def test_invalid_base64_signature(self, valid_signature_payload):
        valid_signature_payload["signature"] = "!!!invalid!!!"
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "signature" in reason

    def test_signer_cert_not_dict(self, valid_signature_payload):
        valid_signature_payload["signer_cert"] = "not-a-dict"
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "signer_cert" in reason

    def test_signer_cert_missing_field(self, valid_signature_payload):
        del valid_signature_payload["signer_cert"]["subject"]
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "signer_cert" in reason
        assert "subject" in reason

    def test_timestamp_in_future(self, valid_signature_payload):
        valid_signature_payload["timestamp"] = time.time() + 3600
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "timestamp" in reason

    def test_timestamp_not_number(self, valid_signature_payload):
        valid_signature_payload["timestamp"] = "not-a-number"
        is_valid, reason = validate_signature_payload(valid_signature_payload)
        assert is_valid is False
        assert "timestamp" in reason


# ============================================================
# Tests for validate_encrypted_message
# ============================================================


class TestValidateEncryptedMessage:
    def test_valid_encrypted_message(self, valid_encrypted_message):
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is True
        assert reason == "valid"

    def test_wrong_version(self, valid_encrypted_message):
        valid_encrypted_message["version"] = 2
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "version" in reason

    def test_wrong_algorithm(self, valid_encrypted_message):
        valid_encrypted_message["algorithm"] = "AES-256-GCM"
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "algorithm" in reason

    def test_iv_wrong_size(self, valid_encrypted_message):
        valid_encrypted_message["iv_b64"] = b64_encode(os.urandom(10))
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "iv_b64" in reason
        assert "12 bytes" in reason

    def test_iv_invalid_base64(self, valid_encrypted_message):
        valid_encrypted_message["iv_b64"] = "!!!invalid!!!"
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "iv_b64" in reason

    def test_tag_wrong_size(self, valid_encrypted_message):
        valid_encrypted_message["tag_b64"] = b64_encode(os.urandom(8))
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "tag_b64" in reason
        assert "16 bytes" in reason

    def test_nonce_wrong_size(self, valid_encrypted_message):
        valid_encrypted_message["nonce_b64"] = b64_encode(os.urandom(8))
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "nonce_b64" in reason
        assert "16 bytes" in reason

    def test_ephemeral_pub_not_pem(self, valid_encrypted_message):
        valid_encrypted_message["ephemeral_pub_b64"] = b64_encode(b"not-a-pem-key")
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "ephemeral_pub_b64" in reason

    def test_ciphertext_empty(self, valid_encrypted_message):
        valid_encrypted_message["ciphertext_b64"] = b64_encode(b"")
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "ciphertext_b64" in reason

    def test_timestamp_not_number(self, valid_encrypted_message):
        valid_encrypted_message["timestamp"] = "not-a-number"
        is_valid, reason = validate_encrypted_message(valid_encrypted_message)
        assert is_valid is False
        assert "timestamp" in reason


# ============================================================
# Tests for validate_key_storage
# ============================================================


class TestValidateKeyStorage:
    def test_valid_key_storage(self, valid_key_storage):
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is True
        assert reason == "valid"

    def test_wrong_version(self, valid_key_storage):
        valid_key_storage["version"] = 2
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "version" in reason

    def test_invalid_key_type(self, valid_key_storage):
        valid_key_storage["key_type"] = "dsa"
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "key_type" in reason

    def test_ecc_key_type_valid(self, valid_key_storage):
        valid_key_storage["key_type"] = "ecc"
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is True

    def test_wrong_algorithm(self, valid_key_storage):
        valid_key_storage["algorithm"] = "AES-256-GCM"
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "algorithm" in reason

    def test_iterations_too_low(self, valid_key_storage):
        valid_key_storage["iterations"] = 50000
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "iterations" in reason

    def test_iterations_exactly_min(self, valid_key_storage):
        valid_key_storage["iterations"] = 100000
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is True

    def test_salt_wrong_size(self, valid_key_storage):
        valid_key_storage["salt_b64"] = b64_encode(os.urandom(8))
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "salt_b64" in reason
        assert "16 bytes" in reason

    def test_iv_wrong_size(self, valid_key_storage):
        valid_key_storage["iv_b64"] = b64_encode(os.urandom(16))
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "iv_b64" in reason
        assert "12 bytes" in reason

    def test_tag_wrong_size(self, valid_key_storage):
        valid_key_storage["tag_b64"] = b64_encode(os.urandom(8))
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "tag_b64" in reason
        assert "16 bytes" in reason

    def test_encrypted_key_empty(self, valid_key_storage):
        valid_key_storage["encrypted_key_b64"] = b64_encode(b"")
        is_valid, reason = validate_key_storage(valid_key_storage)
        assert is_valid is False
        assert "encrypted_key_b64" in reason

"""Checkpoint test: Verify CLI module structure and full integration workflow.

This test verifies:
1. The CLI module imports correctly and has all 8 commands registered.
2. A full end-to-end integration flow works:
   - Initialize CA
   - Generate RSA key pair ("alice")
   - Generate ECC key pair ("bob")
   - Issue cert for alice (RSA)
   - Issue cert for bob (ECC)
   - Sign a test file with alice's key
   - Verify the signature
   - Encrypt the test file for bob
   - Decrypt with bob's key
   - Revoke alice's cert
   - Verify signature with revoked cert → should fail with "revoked"
3. schema_validation works on actual cert and encrypted message data.
"""

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_keystore_and_ca(monkeypatch, tmp_path):
    """Redirect keystore and CA directories to temp dirs for test isolation."""
    keys_dir = tmp_path / "keys"
    ca_dir = tmp_path / "ca"
    keys_dir.mkdir()
    ca_dir.mkdir()

    import securevault.key_manager as km
    import securevault.certificate_authority as ca_mod

    monkeypatch.setattr(km, "KEYSTORE_DIR", keys_dir)
    monkeypatch.setattr(ca_mod, "CA_DIR", ca_dir)


class TestCLIModuleStructure:
    """Verify the CLI module imports and has all 8 commands."""

    def test_import_cli_module(self):
        """CLI module should import without errors."""
        from securevault.securevault_cli import main
        assert callable(main)

    def test_all_8_commands_registered(self):
        """All 8 subcommands should be registered in the CLI parser."""
        from securevault import securevault_cli

        # Build the parser by inspecting main's internals
        # We'll create the parser the same way main() does
        parser = argparse.ArgumentParser(prog="securevault")
        subparsers = parser.add_subparsers(dest="command")

        expected_commands = [
            "init-ca",
            "keygen",
            "issue-cert",
            "sign",
            "verify",
            "encrypt",
            "decrypt",
            "revoke-cert",
        ]

        # Instead of re-creating the parser, test that parsing each command
        # is recognized by the actual CLI. We can test by calling parse_args
        # and checking that the commands exist in the module's main function source.
        import inspect
        source = inspect.getsource(securevault_cli.main)

        for cmd in expected_commands:
            assert f'"{cmd}"' in source or f"'{cmd}'" in source, (
                f"Command '{cmd}' not found in CLI main() source"
            )

    def test_cli_commands_have_handlers(self):
        """Each command should have a corresponding handler function."""
        from securevault import securevault_cli

        handlers = [
            "_cmd_init_ca",
            "_cmd_keygen",
            "_cmd_issue_cert",
            "_cmd_sign",
            "_cmd_verify",
            "_cmd_encrypt",
            "_cmd_decrypt",
            "_cmd_revoke_cert",
        ]

        for handler in handlers:
            assert hasattr(securevault_cli, handler), (
                f"Handler '{handler}' not found in CLI module"
            )
            assert callable(getattr(securevault_cli, handler)), (
                f"Handler '{handler}' is not callable"
            )


class TestFullIntegrationWorkflow:
    """End-to-end integration test of all PKI operations."""

    def test_complete_pki_workflow(self, tmp_path):
        """Test the complete PKI workflow from CA init through revocation."""
        from securevault import (
            certificate_authority as ca,
            key_manager as km,
            signature_engine as se,
            encryption_engine as ee,
        )

        ca_password = "test-ca-pass-2024"
        alice_password = "alice-pass-2024"
        bob_password = "bob-pass-2024"

        # Step 1: Initialize CA
        ca.init_ca(ca_name="Test CA", password=ca_password)
        ca_cert = ca.get_ca_certificate()
        assert ca_cert["subject"] == "Test CA"
        assert ca_cert["issuer"] == "Test CA"
        assert ca_cert["serial"] == 1

        # Step 2: Generate RSA key pair for alice
        km.generate_keypair("alice", key_type="rsa", key_size=4096, password=alice_password)
        alice_pub = km.load_public_key("alice")
        assert alice_pub.startswith(b"-----BEGIN PUBLIC KEY-----")

        # Step 3: Generate ECC key pair for bob
        km.generate_keypair("bob", key_type="ecc", password=bob_password)
        bob_pub = km.load_public_key("bob")
        assert bob_pub.startswith(b"-----BEGIN PUBLIC KEY-----")

        # Step 4: Issue cert for alice (RSA)
        alice_cert = ca.issue_certificate(
            subject="Alice",
            public_key_pem=alice_pub,
            validity_days=365,
            password=ca_password,
        )
        assert alice_cert["subject"] == "Alice"
        assert alice_cert["key_type"] == "rsa"
        assert alice_cert["serial"] == 1000
        assert alice_cert["signature"] != ""

        # Step 5: Issue cert for bob (ECC)
        bob_cert = ca.issue_certificate(
            subject="Bob",
            public_key_pem=bob_pub,
            validity_days=365,
            password=ca_password,
        )
        assert bob_cert["subject"] == "Bob"
        assert bob_cert["key_type"] == "ecc"
        assert bob_cert["serial"] == 1001
        assert bob_cert["signature"] != ""

        # Step 6: Sign a test file with alice's key
        test_file = tmp_path / "document.txt"
        test_file.write_text("This is a test document for signing.", encoding="utf-8")

        alice_priv = km.load_private_key("alice", alice_password)
        signature = se.sign_file(str(test_file), alice_priv, alice_cert)
        assert signature is not None
        sig_data = json.loads(signature)
        assert sig_data["version"] == 1
        assert sig_data["algorithm"] == "RSA-PSS-SHA256"
        assert sig_data["signer_cert"]["subject"] == "Alice"

        # Step 7: Verify the signature
        crl = ca.get_crl()
        is_valid, reason = se.verify_file_signature(
            str(test_file), signature, alice_cert, ca_cert, crl
        )
        assert is_valid is True
        assert reason == "valid"

        # Step 8: Encrypt the test file for bob
        plaintext_content = test_file.read_bytes()
        encrypted_msg = ee.encrypt_message(plaintext_content, bob_cert)
        assert encrypted_msg["version"] == 1
        assert encrypted_msg["algorithm"] == "ECDH-P384+HKDF-SHA256+AES-256-GCM"
        assert "ephemeral_pub_b64" in encrypted_msg
        assert "iv_b64" in encrypted_msg
        assert "tag_b64" in encrypted_msg
        assert "ciphertext_b64" in encrypted_msg
        assert "nonce_b64" in encrypted_msg
        assert "timestamp" in encrypted_msg

        # Step 9: Decrypt with bob's key
        bob_priv = km.load_private_key("bob", bob_password)
        decrypted = ee.decrypt_message(encrypted_msg, bob_priv)
        assert decrypted == plaintext_content

        # Step 10: Revoke alice's cert
        ca.revoke_certificate(serial=alice_cert["serial"], password=ca_password)
        updated_crl = ca.get_crl()
        assert alice_cert["serial"] in updated_crl

        # Step 11: Verify signature with revoked cert → should fail with "revoked"
        is_valid, reason = se.verify_file_signature(
            str(test_file), signature, alice_cert, ca_cert, updated_crl
        )
        assert is_valid is False
        assert reason == "revoked"


class TestSchemaValidationOnRealData:
    """Verify schema validators work on actual cert and encrypted message data."""

    def test_validate_certificate_on_real_cert(self, tmp_path):
        """validate_certificate should accept a real CA-issued certificate."""
        from securevault import certificate_authority as ca, key_manager as km
        from securevault.schema_validation import validate_certificate

        # Set up CA and generate a certificate
        ca.init_ca(ca_name="Schema Test CA", password="schemapass")
        km.generate_keypair("schema_user", key_type="rsa", key_size=4096, password="userpass")
        user_pub = km.load_public_key("schema_user")
        user_cert = ca.issue_certificate(
            subject="SchemaUser",
            public_key_pem=user_pub,
            validity_days=90,
            password="schemapass",
        )

        # Validate the certificate
        is_valid, reason = validate_certificate(user_cert)
        assert is_valid is True, f"Certificate validation failed: {reason}"
        assert reason == "valid"

    def test_validate_encrypted_message_on_real_data(self, tmp_path):
        """validate_encrypted_message should accept a real encrypted message."""
        from securevault import (
            certificate_authority as ca,
            key_manager as km,
            encryption_engine as ee,
        )
        from securevault.schema_validation import validate_encrypted_message

        # Set up CA and create an ECC recipient
        ca.init_ca(ca_name="Enc Test CA", password="encpass")
        km.generate_keypair("enc_bob", key_type="ecc", password="bobpass")
        bob_pub = km.load_public_key("enc_bob")
        bob_cert = ca.issue_certificate(
            subject="EncBob",
            public_key_pem=bob_pub,
            validity_days=90,
            password="encpass",
        )

        # Encrypt a message
        plaintext = b"Sensitive financial data for schema validation test"
        encrypted_msg = ee.encrypt_message(plaintext, bob_cert)

        # Validate the encrypted message schema
        is_valid, reason = validate_encrypted_message(encrypted_msg)
        assert is_valid is True, f"Encrypted message validation failed: {reason}"
        assert reason == "valid"

    def test_validate_certificate_rejects_invalid(self):
        """validate_certificate should reject malformed certificates."""
        from securevault.schema_validation import validate_certificate

        # Missing serial
        bad_cert = {
            "subject": "Bad",
            "public_key": "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----",
            "issuer": "CA",
            "serial": -1,
            "not_before": 100.0,
            "not_after": 200.0,
            "key_type": "rsa",
            "signature": "",
        }
        is_valid, reason = validate_certificate(bad_cert)
        assert is_valid is False
        assert "serial" in reason

    def test_validate_encrypted_message_rejects_invalid(self):
        """validate_encrypted_message should reject malformed messages."""
        from securevault.schema_validation import validate_encrypted_message

        bad_msg = {
            "version": 2,  # Invalid version
            "algorithm": "wrong",
        }
        is_valid, reason = validate_encrypted_message(bad_msg)
        assert is_valid is False

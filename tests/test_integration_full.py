"""Full end-to-end integration tests for SecureVault PKI.

Tests covering all three use cases from the requirements:
- Use Case A: Lawyer document signing (non-repudiation)
- Use Case B: Financial institution encrypted data exchange (forward secrecy)
- Use Case C: SaaS platform certificate revocation (access management)
- Full combined workflow covering all operations
"""

import json
import os

import pytest

import securevault.certificate_authority as ca
import securevault.encryption_engine as ee
import securevault.key_manager as km
import securevault.signature_engine as se
from securevault.pki_utils import verify_certificate


@pytest.fixture(autouse=True)
def setup_temp_dirs(tmp_path, monkeypatch):
    """Configure CA and keystore directories to use tmp_path for isolation.

    Each test gets a fresh temporary directory, ensuring no shared state
    between tests.
    """
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    keystore_dir = tmp_path / "keys"
    keystore_dir.mkdir()

    monkeypatch.setattr(ca, "CA_DIR", ca_dir)
    monkeypatch.setattr(km, "KEYSTORE_DIR", keystore_dir)


class TestUseCaseALawyerWorkflow:
    """Use Case A: Lawyer document signing with non-repudiation."""

    def test_use_case_a_lawyer_workflow(self, tmp_path):
        """Init CA → Generate alice RSA key → Issue cert → Sign document → Verify → (True, 'valid')."""
        ca_password = "ca-lawyer-pass"

        # Step 1: Initialize the CA
        ca.init_ca(ca_name="Law Firm CA", password=ca_password)

        # Step 2: Generate Alice's RSA key pair (lawyers use RSA for signing)
        km.generate_keypair("alice", key_type="rsa", key_size=2048, password="alice-pass")
        alice_pub = km.load_public_key("alice")

        # Step 3: Issue a certificate for Alice
        alice_cert = ca.issue_certificate(
            subject="Alice Attorney",
            public_key_pem=alice_pub,
            validity_days=365,
            password=ca_password,
        )

        # Step 4: Create a document to sign
        document_path = str(tmp_path / "contract.pdf")
        with open(document_path, "wb") as f:
            f.write(b"This is a legally binding contract between parties A and B.")

        # Step 5: Sign the document
        alice_priv = km.load_private_key("alice", password="alice-pass")
        signature = se.sign_file(document_path, alice_priv, alice_cert)
        assert signature is not None
        assert len(signature) > 0

        # Verify signature is valid JSON
        sig_data = json.loads(signature)
        assert sig_data["version"] == 1
        assert sig_data["algorithm"] == "RSA-PSS-SHA256"
        assert sig_data["filename"] == "contract.pdf"

        # Step 6: Verify the signature
        ca_cert = ca.get_ca_certificate()
        crl = ca.get_crl()

        is_valid, reason = se.verify_file_signature(
            document_path, signature, alice_cert, ca_cert, crl
        )
        assert is_valid is True
        assert reason == "valid"


class TestUseCaseBFinanceWorkflow:
    """Use Case B: Financial institution encrypted data exchange with forward secrecy."""

    def test_use_case_b_finance_workflow(self, tmp_path):
        """Init CA → Generate ECC keys for bank_a/bank_b → Issue certs → encrypt → decrypt → match."""
        ca_password = "ca-finance-pass"

        # Step 1: Initialize the CA
        ca.init_ca(ca_name="Finance CA", password=ca_password)

        # Step 2: Generate ECC keys for both banks (ECC needed for hybrid encryption)
        km.generate_keypair("bank_a", key_type="ecc", password="bank-a-pass")
        km.generate_keypair("bank_b", key_type="ecc", password="bank-b-pass")

        bank_a_pub = km.load_public_key("bank_a")
        bank_b_pub = km.load_public_key("bank_b")

        # Step 3: Issue certificates for both banks
        bank_a_cert = ca.issue_certificate(
            subject="Bank A",
            public_key_pem=bank_a_pub,
            validity_days=365,
            password=ca_password,
        )
        bank_b_cert = ca.issue_certificate(
            subject="Bank B",
            public_key_pem=bank_b_pub,
            validity_days=365,
            password=ca_password,
        )

        # Step 4: Bank A encrypts a message for Bank B
        plaintext = b"Transfer $1,000,000 from Account 12345 to Account 67890"
        encrypted = ee.encrypt_message(plaintext, bank_b_cert)

        # Verify encrypted message structure
        assert "ephemeral_pub_b64" in encrypted
        assert "iv_b64" in encrypted
        assert "tag_b64" in encrypted
        assert "ciphertext_b64" in encrypted
        assert "nonce_b64" in encrypted
        assert "timestamp" in encrypted

        # Step 5: Bank B decrypts the message
        bank_b_priv = km.load_private_key("bank_b", password="bank-b-pass")
        decrypted = ee.decrypt_message(encrypted, bank_b_priv)

        # Step 6: Verify plaintext matches
        assert decrypted == plaintext


class TestUseCaseCSaaSWorkflow:
    """Use Case C: SaaS platform certificate revocation for employee access management."""

    def test_use_case_c_saas_workflow(self, tmp_path):
        """Init CA → Issue certs for alice/bob/charlie → Revoke charlie → Verify alice/charlie."""
        ca_password = "ca-saas-pass"

        # Step 1: Initialize the CA
        ca.init_ca(ca_name="SaaS Platform CA", password=ca_password)

        # Step 2: Generate keys for three employees
        km.generate_keypair("alice", key_type="rsa", key_size=2048, password="alice-pass")
        km.generate_keypair("bob", key_type="rsa", key_size=2048, password="bob-pass")
        km.generate_keypair("charlie", key_type="rsa", key_size=2048, password="charlie-pass")

        # Step 3: Issue certificates for all three employees
        alice_cert = ca.issue_certificate(
            subject="Alice Employee",
            public_key_pem=km.load_public_key("alice"),
            validity_days=365,
            password=ca_password,
        )
        bob_cert = ca.issue_certificate(
            subject="Bob Employee",
            public_key_pem=km.load_public_key("bob"),
            validity_days=365,
            password=ca_password,
        )
        charlie_cert = ca.issue_certificate(
            subject="Charlie Employee",
            public_key_pem=km.load_public_key("charlie"),
            validity_days=365,
            password=ca_password,
        )

        # Step 4: Verify all certificates are initially valid
        ca_cert = ca.get_ca_certificate()
        ca_pub_pem = ca_cert["public_key"].encode("utf-8")
        crl = ca.get_crl()

        for cert in [alice_cert, bob_cert, charlie_cert]:
            is_valid, reason = verify_certificate(cert, ca_pub_pem, crl)
            assert is_valid is True

        # Step 5: Charlie leaves the company — revoke their certificate
        ca.revoke_certificate(serial=charlie_cert["serial"], password=ca_password)

        # Step 6: Verify Alice is still valid
        crl = ca.get_crl()
        is_valid, reason = verify_certificate(alice_cert, ca_pub_pem, crl)
        assert is_valid is True
        assert reason == "valid"

        # Step 7: Verify Charlie is revoked
        is_valid, reason = verify_certificate(charlie_cert, ca_pub_pem, crl)
        assert is_valid is False
        assert reason == "revoked"

        # Bob should also still be valid
        is_valid, reason = verify_certificate(bob_cert, ca_pub_pem, crl)
        assert is_valid is True
        assert reason == "valid"


class TestFullWorkflowSignVerifyEncryptDecrypt:
    """Complete end-to-end workflow combining signing, encryption, and revocation."""

    def test_full_workflow_sign_verify_encrypt_decrypt(self, tmp_path):
        """Complete end-to-end workflow combining everything."""
        ca_password = "full-workflow-pass"

        # ===== SETUP: Initialize CA =====
        ca.init_ca(ca_name="Full Workflow CA", password=ca_password)
        ca_cert = ca.get_ca_certificate()

        # ===== Generate keys for different purposes =====
        # RSA key for signing
        km.generate_keypair("signer", key_type="rsa", key_size=2048, password="signer-pass")
        # ECC keys for encryption
        km.generate_keypair("sender_enc", key_type="ecc", password="sender-pass")
        km.generate_keypair("recipient", key_type="ecc", password="recipient-pass")

        # ===== Issue certificates =====
        signer_cert = ca.issue_certificate(
            subject="Document Signer",
            public_key_pem=km.load_public_key("signer"),
            validity_days=365,
            password=ca_password,
        )
        recipient_cert = ca.issue_certificate(
            subject="Message Recipient",
            public_key_pem=km.load_public_key("recipient"),
            validity_days=365,
            password=ca_password,
        )

        # ===== SIGNING WORKFLOW =====
        # Create a document
        doc_path = str(tmp_path / "report.txt")
        doc_content = b"Quarterly financial report - Q4 2024. Revenue: $10M."
        with open(doc_path, "wb") as f:
            f.write(doc_content)

        # Sign the document
        signer_priv = km.load_private_key("signer", password="signer-pass")
        signature = se.sign_file(doc_path, signer_priv, signer_cert)

        # Verify the signature is valid
        crl = ca.get_crl()
        is_valid, reason = se.verify_file_signature(
            doc_path, signature, signer_cert, ca_cert, crl
        )
        assert is_valid is True
        assert reason == "valid"

        # Verify tampering is detected
        tampered_path = str(tmp_path / "tampered_report.txt")
        with open(tampered_path, "wb") as f:
            f.write(b"MODIFIED: Quarterly financial report - Q4 2024. Revenue: $100M.")

        is_valid, reason = se.verify_file_signature(
            tampered_path, signature, signer_cert, ca_cert, crl
        )
        assert is_valid is False
        assert reason == "bad_signature"

        # ===== ENCRYPTION WORKFLOW =====
        # Encrypt a message for the recipient
        secret_message = b"Confidential: merger details - acquire CompanyX for $500M"
        encrypted = ee.encrypt_message(secret_message, recipient_cert)

        # Decrypt with recipient's private key
        recipient_priv = km.load_private_key("recipient", password="recipient-pass")
        decrypted = ee.decrypt_message(encrypted, recipient_priv)
        assert decrypted == secret_message

        # ===== FILE ENCRYPTION WORKFLOW =====
        secret_file_path = str(tmp_path / "secret.txt")
        with open(secret_file_path, "wb") as f:
            f.write(b"Top secret file contents for encryption test")

        # Encrypt the file
        encrypted_file_path = str(tmp_path / "secret.txt.enc")
        ee.encrypt_file(secret_file_path, recipient_cert, output_path=encrypted_file_path)
        assert os.path.exists(encrypted_file_path)

        # Decrypt the file
        decrypted_file_path = str(tmp_path / "secret_decrypted.txt")
        ee.decrypt_file(encrypted_file_path, recipient_priv, output_path=decrypted_file_path)

        # Verify decrypted content matches original
        with open(decrypted_file_path, "rb") as f:
            decrypted_content = f.read()
        assert decrypted_content == b"Top secret file contents for encryption test"

        # ===== REVOCATION WORKFLOW =====
        # Revoke the signer's certificate
        ca.revoke_certificate(serial=signer_cert["serial"], password=ca_password)

        # Verify signature now fails due to revocation
        crl = ca.get_crl()
        is_valid, reason = se.verify_file_signature(
            doc_path, signature, signer_cert, ca_cert, crl
        )
        assert is_valid is False
        assert reason == "revoked"

        # ===== MESSAGE SIGNING WORKFLOW =====
        # Use a non-revoked key for message signing
        km.generate_keypair("msg_signer", key_type="rsa", key_size=2048, password="msg-pass")
        msg_signer_cert = ca.issue_certificate(
            subject="Message Signer",
            public_key_pem=km.load_public_key("msg_signer"),
            validity_days=365,
            password=ca_password,
        )
        msg_signer_priv = km.load_private_key("msg_signer", password="msg-pass")

        # Sign and verify an in-memory message
        message = b"This is a signed protocol message"
        msg_signature = se.sign_message(message, msg_signer_priv, msg_signer_cert)

        is_valid, reason = se.verify_message_signature(
            message, msg_signature, msg_signer_cert, ca_cert, crl
        )
        assert is_valid is True
        assert reason == "valid"

        # Verify tampered message is detected
        is_valid, reason = se.verify_message_signature(
            b"Tampered message content", msg_signature, msg_signer_cert, ca_cert, crl
        )
        assert is_valid is False
        assert reason == "bad_signature"

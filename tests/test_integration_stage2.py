"""Integration tests for CA and Key Management — Stage 2.

Tests covering Certificate Authority initialization, certificate issuance,
CRL management, and key generation/loading lifecycle.
"""

import json

import pytest

import securevault.certificate_authority as ca
import securevault.key_manager as km
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


class TestCAInitAndCertificateLifecycle:
    """Test CA initialization → certificate issuance → verify → revoke → verify revoked."""

    def test_ca_init_and_certificate_lifecycle(self, tmp_path):
        """Full lifecycle: init CA → issue cert → verify valid → revoke → verify revoked."""
        ca_password = "test-ca-password"

        # Step 1: Initialize the CA
        ca.init_ca(ca_name="Test CA", password=ca_password)

        # Verify CA certificate exists and is retrievable
        ca_cert = ca.get_ca_certificate()
        assert ca_cert["subject"] == "Test CA"
        assert ca_cert["issuer"] == "Test CA"
        assert ca_cert["serial"] == 1

        # Step 2: Generate a user key pair
        km.generate_keypair("alice", key_type="rsa", key_size=2048, password="alice-pass")
        alice_pub = km.load_public_key("alice")

        # Step 3: Issue a certificate for Alice
        alice_cert = ca.issue_certificate(
            subject="Alice Smith",
            public_key_pem=alice_pub,
            validity_days=365,
            password=ca_password,
        )
        assert alice_cert["subject"] == "Alice Smith"
        assert alice_cert["serial"] == 1000
        assert alice_cert["signature"] != ""

        # Step 4: Verify the certificate is valid
        ca_pub_pem = ca_cert["public_key"].encode("utf-8")
        crl = ca.get_crl()
        is_valid, reason = verify_certificate(alice_cert, ca_pub_pem, crl)
        assert is_valid is True
        assert reason == "valid"

        # Step 5: Revoke Alice's certificate
        ca.revoke_certificate(serial=1000, password=ca_password)

        # Step 6: Verify the certificate is now revoked
        crl = ca.get_crl()
        assert 1000 in crl
        is_valid, reason = verify_certificate(alice_cert, ca_pub_pem, crl)
        assert is_valid is False
        assert reason == "revoked"


class TestKeyGenerationAndLoading:
    """Test key generation and loading with correct/incorrect passwords."""

    def test_key_generation_and_loading(self, tmp_path):
        """Generate RSA & ECC keys → load with correct/wrong password."""
        # Generate RSA key pair
        km.generate_keypair("rsa_key", key_type="rsa", key_size=2048, password="rsa-pass")

        # Generate ECC key pair
        km.generate_keypair("ecc_key", key_type="ecc", password="ecc-pass")

        # Load RSA private key with correct password
        rsa_priv = km.load_private_key("rsa_key", password="rsa-pass")
        assert rsa_priv is not None
        assert b"PRIVATE KEY" in rsa_priv

        # Load ECC private key with correct password
        ecc_priv = km.load_private_key("ecc_key", password="ecc-pass")
        assert ecc_priv is not None
        assert b"PRIVATE KEY" in ecc_priv

        # Load public keys (no password needed)
        rsa_pub = km.load_public_key("rsa_key")
        assert b"PUBLIC KEY" in rsa_pub

        ecc_pub = km.load_public_key("ecc_key")
        assert b"PUBLIC KEY" in ecc_pub

        # Attempt to load with wrong password should raise ValueError
        with pytest.raises(ValueError, match="Incorrect password"):
            km.load_private_key("rsa_key", password="wrong-password")

        with pytest.raises(ValueError, match="Incorrect password"):
            km.load_private_key("ecc_key", password="wrong-password")


class TestCAIssuesMultipleCerts:
    """Test issuing multiple certificates and verifying serial increments."""

    def test_ca_issues_multiple_certs(self, tmp_path):
        """Issue multiple certs, verify serial numbers increment."""
        ca_password = "multi-cert-pass"
        ca.init_ca(ca_name="Multi CA", password=ca_password)

        # Generate keys for multiple users
        km.generate_keypair("user1", key_type="rsa", key_size=2048, password="p1")
        km.generate_keypair("user2", key_type="rsa", key_size=2048, password="p2")
        km.generate_keypair("user3", key_type="rsa", key_size=2048, password="p3")

        # Issue certificates
        cert1 = ca.issue_certificate(
            subject="User One",
            public_key_pem=km.load_public_key("user1"),
            validity_days=365,
            password=ca_password,
        )
        cert2 = ca.issue_certificate(
            subject="User Two",
            public_key_pem=km.load_public_key("user2"),
            validity_days=365,
            password=ca_password,
        )
        cert3 = ca.issue_certificate(
            subject="User Three",
            public_key_pem=km.load_public_key("user3"),
            validity_days=365,
            password=ca_password,
        )

        # Verify serial numbers are incrementing starting from 1000
        assert cert1["serial"] == 1000
        assert cert2["serial"] == 1001
        assert cert3["serial"] == 1002

        # Verify all certificates are valid
        ca_cert = ca.get_ca_certificate()
        ca_pub_pem = ca_cert["public_key"].encode("utf-8")
        crl = ca.get_crl()

        for cert in [cert1, cert2, cert3]:
            is_valid, reason = verify_certificate(cert, ca_pub_pem, crl)
            assert is_valid is True, f"Certificate serial {cert['serial']} should be valid"


class TestCRLPersistsAcrossReloads:
    """Test that CRL persists across reloads."""

    def test_crl_persists_across_reloads(self, tmp_path):
        """Revoke cert, reload CRL, cert still revoked."""
        ca_password = "crl-persist-pass"
        ca.init_ca(ca_name="CRL CA", password=ca_password)

        # Issue a certificate
        km.generate_keypair("bob", key_type="rsa", key_size=2048, password="bob-pass")
        bob_cert = ca.issue_certificate(
            subject="Bob Jones",
            public_key_pem=km.load_public_key("bob"),
            validity_days=365,
            password=ca_password,
        )

        # Revoke the certificate
        ca.revoke_certificate(serial=bob_cert["serial"], password=ca_password)

        # First check: cert is revoked
        crl1 = ca.get_crl()
        assert bob_cert["serial"] in crl1

        # Simulate "reload" by fetching CRL again (it reads from disk)
        crl2 = ca.get_crl()
        assert bob_cert["serial"] in crl2

        # Verify the certificate is still revoked after reload
        ca_cert = ca.get_ca_certificate()
        ca_pub_pem = ca_cert["public_key"].encode("utf-8")
        is_valid, reason = verify_certificate(bob_cert, ca_pub_pem, crl2)
        assert is_valid is False
        assert reason == "revoked"

        # Verify the CRL file on disk contains the serial
        crl_path = ca.CA_DIR / "crl.json"
        crl_data = json.loads(crl_path.read_text(encoding="utf-8"))
        assert bob_cert["serial"] in crl_data["serials"]

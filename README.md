# SecureVault PKI

A comprehensive open-source Public Key Infrastructure (PKI) toolkit implemented in Python. SecureVault provides digital signatures with non-repudiation, hybrid encryption with forward secrecy, and full certificate lifecycle management — all powered by modern, audited cryptographic primitives.

## Features

- **AES-256-GCM Authenticated Encryption** — Confidentiality and integrity in a single operation with 12-byte IV and 16-byte authentication tag
- **RSA-PSS Digital Signatures** — 4096-bit RSA keys with Probabilistic Signature Scheme (SHA-256) for non-repudiation
- **Hybrid Encryption with Forward Secrecy** — Ephemeral ECDH (P-384) + HKDF-SHA256 + AES-256-GCM; ephemeral keys are deleted immediately after use
- **Certificate Management** — JSON-based certificates with CA signing, serial tracking, and validity enforcement
- **Certificate Revocation Lists (CRL)** — Persistent revocation management with serial-based lookup
- **Replay Protection** — Thread-safe nonce cache with configurable time window and automatic eviction
- **Encrypted Key Storage** — PBKDF2-SHA256 (100,000 iterations) + AES-256-GCM protects private keys at rest
- **Structured Security Logging** — JSON-formatted audit logs that never expose key material

## Threat Model & Scope

### In-Scope Threats

| Threat | Mitigation |
|--------|-----------|
| Man-in-the-Middle (MITM) | Certificate chain validation with CA signatures |
| Replay Attacks | Nonce cache + timestamp window (60s default) |
| Message Tampering | AES-256-GCM authentication tags |
| Key Exposure at Rest | PBKDF2 + AES-256-GCM encrypted keystore |
| Certificate Forgery | RSA-PSS CA signature verification |

### Out-of-Scope Threats

- Traffic analysis and metadata leakage
- Side-channel attacks (timing partially mitigated via `hmac.compare_digest`)
- Malicious CA operator
- Denial of Service (DoS)
- Hardware-level attacks

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/DarkTunnel-PKI.git
cd DarkTunnel-PKI

# Install in development mode with all dependencies
pip install -e ".[dev]"
```

### Dependencies

- **Runtime:** `cryptography>=42.0.0`
- **Development:** `pytest>=7.0`, `hypothesis>=6.0`, `coverage>=7.0`, `pytest-cov>=4.0`
- **Python:** 3.11+

## Quick Start

```python
from securevault import certificate_authority as ca, key_manager as km
from securevault import signature_engine as se, encryption_engine as ee

# 1. Initialize the Certificate Authority
ca.init_ca(ca_name="MyOrg CA", password="ca-secret")

# 2. Generate a key pair
km.generate_keypair("alice", key_type="rsa", key_size=4096, password="alice-pass")

# 3. Issue a certificate
alice_pub = km.load_public_key("alice")
alice_cert = ca.issue_certificate(
    subject="Alice", public_key_pem=alice_pub,
    validity_days=365, password="ca-secret"
)

# 4. Sign a document
alice_priv = km.load_private_key("alice", password="alice-pass")
signature = se.sign_file("contract.pdf", alice_priv, alice_cert)
with open("contract.pdf.sig", "wb") as f:
    f.write(signature)

# 5. Verify the signature
ca_cert = ca.get_ca_certificate()
crl = ca.get_crl()
is_valid, reason = se.verify_file_signature(
    "contract.pdf", signature, alice_cert, ca_cert, crl
)
print(f"Valid: {is_valid}, Reason: {reason}")

# 6. Encrypt a message (hybrid encryption with forward secrecy)
km.generate_keypair("bob", key_type="ecc", password="bob-pass")
bob_pub = km.load_public_key("bob")
bob_cert = ca.issue_certificate(
    subject="Bob", public_key_pem=bob_pub,
    validity_days=365, password="ca-secret"
)

encrypted = ee.encrypt_message(b"Confidential data", bob_cert)

# 7. Decrypt the message
bob_priv = km.load_private_key("bob", password="bob-pass")
plaintext = ee.decrypt_message(encrypted, bob_priv)
```

## CLI Usage

SecureVault provides 8 CLI commands for all PKI operations:

### Initialize Certificate Authority

```bash
securevault init-ca --name "MyOrg CA" --password "ca-secret"
```

### Generate Key Pair

```bash
# RSA key (for signatures)
securevault keygen --name alice --type rsa --size 4096 --password "key-pass"

# ECC key (for encryption)
securevault keygen --name bob --type ecc --password "key-pass"
```

### Issue Certificate

```bash
securevault issue-cert --subject "Alice" --pubkey alice.pub --days 365 --ca-password "ca-secret"
```

### Sign a File

```bash
securevault sign --file report.pdf --key alice --password "key-pass" --cert Alice.cert.json
```

### Verify a Signature

```bash
securevault verify --file report.pdf --sig report.pdf.sig --ca-cert ca.cert.json
```

### Encrypt a File

```bash
securevault encrypt --file secret.txt --cert bob-cert.json
```

### Decrypt a File

```bash
securevault decrypt --file secret.txt.enc --key bob --password "bob-pass"
```

### Revoke a Certificate

```bash
securevault revoke-cert --serial 1001 --ca-password "ca-secret"
```

## Running Tests

```bash
# Run all tests with coverage
pytest tests/ --cov=securevault

# Run with verbose output
pytest tests/ -v --tb=short

# Run specific test modules
pytest tests/test_schema_validation.py

# Generate HTML coverage report
pytest tests/ --cov=securevault --cov-report=html
```

**Coverage Target:** 85%+ line coverage

## Architecture

SecureVault follows a layered architecture with clean separation of concerns:

```
┌─────────────────────────────────────────────────┐
│              Presentation Layer                   │
│            securevault_cli.py                     │
├─────────────────────────────────────────────────┤
│              Application Layer                    │
│    signature_engine.py  │  encryption_engine.py  │
├─────────────────────────────────────────────────┤
│                Domain Layer                       │
│  certificate_authority.py │ key_manager.py       │
│            replay_protection.py                  │
├─────────────────────────────────────────────────┤
│            Infrastructure Layer                   │
│  crypto_utils.py │ pki_utils.py │ logging_utils  │
└─────────────────────────────────────────────────┘
```

| Module | Responsibility |
|--------|---------------|
| `crypto_utils.py` | AES-GCM, RSA-PSS, ECDH, HKDF, base64 utilities |
| `pki_utils.py` | Certificate structures, canonical JSON, chain validation |
| `key_manager.py` | Key generation, encrypted storage, keystore operations |
| `certificate_authority.py` | CA init, cert issuance, CRL management |
| `signature_engine.py` | File/message signing and verification |
| `encryption_engine.py` | Hybrid encryption/decryption with forward secrecy |
| `replay_protection.py` | Nonce cache, timestamp validation, replay detection |
| `logging_utils.py` | Structured JSON security logging |
| `schema_validation.py` | Input validation for certificates, signatures, messages |
| `securevault_cli.py` | CLI entry point with argparse |

For detailed architecture information, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/my-feature`)
3. **Develop** with tests (`pytest tests/ --cov=securevault`)
4. **Submit** a Pull Request

See [docs/CONTRIBUTION.md](docs/CONTRIBUTION.md) for detailed contribution guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

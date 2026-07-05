# Implementation Plan: SecureVault PKI

## Overview

This implementation plan follows an 8-stage approach building from cryptographic primitives upward through key management, digital signatures, hybrid encryption, replay protection, CLI interface, and comprehensive testing/documentation. Each stage builds on the previous, ensuring no orphaned or hanging code. All code uses Python 3.11+ with the `cryptography` library as the sole crypto provider.

## Tasks

- [x] 1. Cryptographic Foundation
  - [x] 1.1 Create project structure and core crypto_utils module
    - Create `securevault/` package with `__init__.py`
    - Implement `crypto_utils.py` with: `aes_encrypt`, `aes_decrypt`, `rsa_keygen`, `ecdh_keygen`, `rsa_sign`, `rsa_verify`, `ecdh_derive_shared_secret`, `hkdf_expand`, `b64_encode`, `b64_decode`, `constant_time_compare`
    - AES-256-GCM: 12-byte IV from CSPRNG, 16-byte tag, AAD support
    - RSA-4096 with PSS padding and SHA-256
    - ECC P-384 (secp384r1) key generation
    - ECDH shared secret derivation and HKDF-SHA256 key derivation
    - Raise `ValueError` for invalid key lengths (not 32 bytes for AES)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4_

  - [ ]* 1.2 Write property tests for crypto_utils
    - **Property 1: AES-256-GCM Encryption-Decryption Round Trip**
    - **Validates: Requirements 1.1, 1.2**
    - **Property 2: AES-GCM Tamper Detection**
    - **Validates: Requirements 1.4, 1.5**
    - **Property 3: RSA-PSS Sign-Verify Round Trip**
    - **Validates: Requirements 2.2, 2.3**
    - **Property 4: RSA-PSS Invalid Signature Rejection**
    - **Validates: Requirement 2.4**
    - **Property 5: ECDH Commutativity**
    - **Validates: Requirement 3.4**
    - **Property 6: HKDF Output Length**
    - **Validates: Requirement 3.3**
    - **Property 22: Invalid Key Length Rejection**
    - **Validates: Requirement 1.3**

  - [x] 1.3 Implement pki_utils module
    - Implement `pki_utils.py` with: `create_cert`, `sign_certificate`, `verify_certificate`, `canonical_json`, `serialize_cert_to_json`, `deserialize_cert_from_json`, `load_pem_public_key`, `load_pem_private_key`
    - Certificate schema: subject, public_key, issuer, serial, not_before, not_after, key_type, signature
    - Validation order: temporal → revocation → signature
    - Canonical JSON: sorted keys, no whitespace, ASCII-safe
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ]* 1.4 Write property tests for pki_utils
    - **Property 7: Canonical JSON Determinism**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    - **Property 8: Certificate Serialization Round Trip**
    - **Validates: Requirement 6.5**
    - **Property 9: Certificate Validation — Valid Certificates Accepted**
    - **Validates: Requirement 5.1**
    - **Property 10: Certificate Validation — Expired Certificates Rejected**
    - **Validates: Requirement 5.2**
    - **Property 11: Certificate Validation — Revoked Certificates Rejected**
    - **Validates: Requirement 5.4**

- [x] 2. Checkpoint - Verify cryptographic foundation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Key Management & Storage
  - [x] 3.1 Implement key_manager module
    - Implement `key_manager.py` with: `generate_keypair`, `load_private_key`, `load_public_key`, `list_keys`, `delete_key`
    - PBKDF2-SHA256 with 100,000 iterations for password-based key derivation
    - AES-256-GCM encryption of private key PEM at rest
    - Storage format: JSON with version, key_type, algorithm, salt, iterations, iv, tag, encrypted_key
    - Public key stored as unencrypted PEM
    - Keystore directory: `~/.securevault/keys/`
    - Raise `FileExistsError` for duplicate names, `FileNotFoundError` for missing keys, `ValueError` for wrong passwords
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8_

  - [ ]* 3.2 Write property tests for key_manager
    - **Property 19: Key Confidentiality at Rest**
    - **Validates: Requirement 7.6**
    - **Property 20: Wrong Password Rejection**
    - **Validates: Requirement 7.3**
    - **Property 21: Key Storage Round Trip**
    - **Validates: Requirement 7.2**

  - [x] 3.3 Implement certificate_authority module
    - Implement `certificate_authority.py` with: `init_ca`, `issue_certificate`, `revoke_certificate`, `get_ca_certificate`, `get_crl`, `verify_issued_cert`
    - CA initialization: RSA-4096 key pair, self-signed cert, empty CRL, serial counter at 1000
    - Certificate issuance with CA signature and serial increment
    - CRL management with persistence
    - CA directory: `~/.securevault/ca/`
    - Raise `RuntimeError` if CA not initialized, `ValueError` for wrong password or invalid serial
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ]* 3.4 Write unit tests for certificate_authority
    - Test CA initialization creates all required artifacts
    - Test certificate issuance with serial increment
    - Test revocation adds serial to CRL
    - Test error cases: uninitialized CA, wrong password, invalid serial
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

- [x] 4. Checkpoint - Verify key management layer
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Digital Signatures
  - [x] 5.1 Implement signature_engine module
    - Implement `signature_engine.py` with: `sign_file`, `sign_message`, `verify_file_signature`, `verify_message_signature`
    - File signing: read file → SHA-256 hash → RSA-PSS sign → JSON package (version, algorithm, signature, signer_cert, timestamp, filename)
    - Verification: certificate chain validation → signature verification (in that order)
    - Log all signing and verification events via logging_utils
    - Raise `FileNotFoundError` for missing files
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 10.1, 10.2, 10.3, 10.4, 10.5_

  - [ ]* 5.2 Write property tests for signature_engine
    - **Property 12: Signature Engine Sign-Verify Round Trip**
    - **Validates: Requirements 9.1, 9.2, 10.1**
    - **Property 13: Signature Engine Tamper Detection**
    - **Validates: Requirement 10.2**

- [x] 6. Hybrid Encryption
  - [x] 6.1 Implement encryption_engine module
    - Implement `encryption_engine.py` with: `encrypt_message`, `encrypt_file`, `decrypt_message`, `decrypt_file`
    - Hybrid encryption: ephemeral ECDH P-384 → shared secret → HKDF-SHA256 → AES-256-GCM
    - Forward secrecy: delete ephemeral private key and shared secret after use
    - Encrypted message schema: version, algorithm, ephemeral_pub_b64, iv_b64, tag_b64, ciphertext_b64, nonce_b64, timestamp
    - File encryption/decryption with .enc extension
    - Reject non-ECC recipient certificates
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 12.1, 12.2, 12.3_

  - [ ]* 6.2 Write property tests for encryption_engine
    - **Property 14: Hybrid Encryption-Decryption Round Trip**
    - **Validates: Requirements 11.1, 11.2, 11.3**
    - **Property 15: Forward Secrecy — Ephemeral Key Uniqueness**
    - **Validates: Requirement 11.5**

- [x] 7. Checkpoint - Verify signatures and encryption
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Replay Protection & Logging
  - [x] 8.1 Implement replay_protection module
    - Implement `replay_protection.py` with `ReplayProtector` class: `check_nonce`, `_evict_stale_nonces`, `generate_nonce`
    - Thread-safe nonce cache using `threading.Lock`
    - Configurable time window (default 60 seconds)
    - Timestamp validation: reject expired (> window) and future (> 5s ahead)
    - Automatic eviction of stale nonces on each check
    - CSPRNG nonce generation (16 bytes)
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7_

  - [ ]* 8.2 Write property tests for replay_protection
    - **Property 16: Replay Detection**
    - **Validates: Requirements 13.1, 13.2**
    - **Property 17: Timestamp Expiry Enforcement**
    - **Validates: Requirement 13.3**
    - **Property 18: Future Timestamp Rejection**
    - **Validates: Requirement 13.4**

  - [x] 8.3 Implement logging_utils module
    - Implement `logging_utils.py` with: `setup_logging`, `log_event`
    - JSON-formatted log entries: timestamp, component, event, result, details
    - Configurable log levels and output destinations (file or stdout)
    - Never log private key material, passwords, or derived keys
    - _Requirements: 14.1, 14.2, 14.3, 14.4_

  - [ ]* 8.4 Write unit tests for logging_utils
    - Verify JSON format of log entries
    - Verify no key material appears in logs
    - Test configurable log levels and output destinations
    - _Requirements: 14.1, 14.2, 14.3, 14.4_

- [x] 9. Checkpoint - Verify replay protection and logging
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. CLI Interface & Integration
  - [x] 10.1 Implement securevault_cli module
    - Implement `securevault_cli.py` using click or argparse
    - Commands: `init-ca`, `keygen`, `issue-cert`, `sign`, `verify`, `encrypt`, `decrypt`, `revoke-cert`
    - Each command delegates to appropriate module (certificate_authority, key_manager, signature_engine, encryption_engine)
    - Descriptive error messages with non-zero exit codes on failure
    - Wire all components together through CLI entry point
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9_

  - [x] 10.2 Implement data schema validation
    - Add validation functions for certificate, signature, encrypted message, and key storage schemas
    - Validate at entry points: certificate processing, signature processing, encryption processing, key storage processing
    - Clear error messages for malformed data
    - _Requirements: 16.1, 16.2, 16.3, 16.4_

  - [ ]* 10.3 Write integration tests for CLI
    - Test full workflow: init-ca → keygen → issue-cert → sign → verify → encrypt → decrypt → revoke → verify-fails
    - Test error cases for each CLI command
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9_

- [x] 11. Checkpoint - Verify CLI and integration
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Testing, Documentation & Project Setup
  - [x] 12.1 Write comprehensive integration tests
    - Create `tests/test_integration_stage2.py`: CA init → cert issuance end-to-end flow
    - Create `tests/test_integration_full.py`: Complete workflow from CA setup through sign/verify/encrypt/decrypt/revoke
    - _Requirements: 8.1, 8.2, 9.1, 10.1, 11.1, 11.3_

  - [ ]* 12.2 Write attack simulation tests
    - Create `tests/test_attacks.py` with: tampered ciphertext detection, forged certificate rejection, expired certificate rejection, replayed message detection, wrong-key decryption failure, timing attack resistance for constant_time_compare
    - _Requirements: 1.4, 5.2, 5.4, 5.5, 10.2, 13.2_

  - [x] 12.3 Create project setup and configuration files
    - Create `setup.py` or `pyproject.toml` with dependencies: cryptography>=42.0.0, click>=8.0, pytest>=7.0, hypothesis>=6.0, coverage>=7.0
    - Create `.gitignore` for Python projects (venv, __pycache__, .coverage, etc.)
    - Create `pytest.ini` or `pyproject.toml` test configuration
    - Create `requirements.txt` and `requirements-dev.txt`
    - _Requirements: All (project infrastructure)_

  - [x] 12.4 Create documentation files
    - Create `README.md` with project overview, installation, quick start, CLI usage examples, and security considerations
    - Create `docs/ARCHITECTURE.md` describing the layered architecture and module relationships
    - Create `docs/CRYPTO_PRIMITIVES.md` documenting all algorithms and their parameters
    - Create `docs/THREAT_MODEL.md` summarizing threats, mitigations, and known limitations
    - _Requirements: All (documentation)_

- [x] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The implementation order ensures no orphaned code: each stage builds on the previous
- All cryptographic operations use the `cryptography` library — no custom crypto implementations
- Python 3.11+ is required for modern type hints and performance
- The `hypothesis` library is used for property-based testing

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["1.4", "3.1", "8.3"] },
    { "id": 3, "tasks": ["3.2", "3.3", "8.4"] },
    { "id": 4, "tasks": ["3.4", "5.1", "8.1"] },
    { "id": 5, "tasks": ["5.2", "6.1", "8.2"] },
    { "id": 6, "tasks": ["6.2", "10.1", "10.2"] },
    { "id": 7, "tasks": ["10.3", "12.1"] },
    { "id": 8, "tasks": ["12.2", "12.3", "12.4"] }
  ]
}
```

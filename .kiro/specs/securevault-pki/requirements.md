# Requirements Document

## Introduction

SecureVault PKI is an open-source cryptographic toolkit implementing a complete Public Key Infrastructure (PKI) system in Python. It provides authenticated encryption (AES-256-GCM), digital signatures (RSA-PSS), hybrid encryption with forward secrecy (ephemeral ECDH + AES-256-GCM), secure key management with encrypted-at-rest private keys (PBKDF2 + AES-256-GCM), JSON-based certificate management with Certificate Revocation Lists, and a CLI interface for all operations.

The system targets educational and demonstration use cases including lawyer document signing (non-repudiation), financial institution encrypted data exchange (forward secrecy, replay protection), and SaaS platform certificate revocation for employee access management.

## Glossary

- **System**: The SecureVault PKI toolkit as a whole
- **Crypto_Module**: The crypto_utils component providing low-level cryptographic primitives
- **PKI_Module**: The pki_utils component managing certificate structures and validation
- **Key_Manager**: The key_manager component handling key generation and encrypted storage
- **Certificate_Authority**: The certificate_authority component managing CA operations, certificate issuance, and CRL
- **Signature_Engine**: The signature_engine component orchestrating file and message signing/verification
- **Encryption_Engine**: The encryption_engine component implementing hybrid encryption/decryption
- **Replay_Protector**: The replay_protection component preventing replay attacks via nonce cache and timestamps
- **Logger**: The logging_utils component providing structured security logging
- **CLI**: The securevault_cli command-line interface entry point
- **AES-256-GCM**: Authenticated encryption with 256-bit key, 96-bit IV, and 128-bit authentication tag
- **RSA-PSS**: RSA Probabilistic Signature Scheme with SHA-256
- **ECDH**: Elliptic Curve Diffie-Hellman key agreement on P-384 curve
- **HKDF-SHA256**: HMAC-based Key Derivation Function using SHA-256
- **PBKDF2**: Password-Based Key Derivation Function 2 with SHA-256 and minimum 100,000 iterations
- **CRL**: Certificate Revocation List — a set of serial numbers identifying revoked certificates
- **Canonical_JSON**: Deterministic JSON serialization with sorted keys, no whitespace, and ASCII encoding
- **Ephemeral_Key**: A temporary ECDH key pair generated per encryption operation and deleted immediately after use
- **Forward_Secrecy**: Property ensuring past communications remain secure even if long-term keys are compromised
- **Nonce**: A cryptographically random 16-byte value used exactly once for replay protection
- **Keystore**: The encrypted storage directory (~/.securevault/keys) containing private and public keys

## Requirements

### Requirement 1: AES-256-GCM Authenticated Encryption

**User Story:** As a developer, I want authenticated symmetric encryption, so that data confidentiality and integrity are guaranteed in a single operation.

#### Acceptance Criteria

1. WHEN plaintext and a 256-bit key are provided, THE Crypto_Module SHALL encrypt the plaintext using AES-256-GCM and return a 12-byte IV, ciphertext of equal length to plaintext, and a 16-byte authentication tag
2. WHEN ciphertext, IV, tag, and the correct key are provided, THE Crypto_Module SHALL decrypt and return the original plaintext
3. IF the key is not exactly 32 bytes, THEN THE Crypto_Module SHALL raise a ValueError
4. IF any byte of the ciphertext, IV, or tag has been modified, THEN THE Crypto_Module SHALL raise an InvalidTag exception during decryption
5. WHEN additional authenticated data (AAD) is provided during encryption, THE Crypto_Module SHALL authenticate the AAD without encrypting it, and decryption SHALL fail if the AAD does not match
6. THE Crypto_Module SHALL generate all IVs from a cryptographically secure random number generator (CSPRNG)

### Requirement 2: RSA Key Generation and Digital Signatures

**User Story:** As a developer, I want RSA key generation and RSA-PSS signing, so that documents can be signed with non-repudiation guarantees.

#### Acceptance Criteria

1. WHEN RSA key generation is requested, THE Crypto_Module SHALL generate a 4096-bit RSA key pair and return private and public keys in PEM format
2. WHEN a message and private key are provided, THE Crypto_Module SHALL produce an RSA-PSS signature using SHA-256 and return a base64-encoded signature string
3. WHEN a message, valid signature, and corresponding public key are provided, THE Crypto_Module SHALL return True
4. WHEN a message, invalid signature, and public key are provided, THE Crypto_Module SHALL return False without raising an exception
5. THE Crypto_Module SHALL use PSS padding with maximum salt length for all RSA signatures

### Requirement 3: ECC Key Generation and ECDH Key Agreement

**User Story:** As a developer, I want ECC key generation and ECDH key agreement, so that ephemeral shared secrets can be derived for hybrid encryption.

#### Acceptance Criteria

1. WHEN ECC key generation is requested, THE Crypto_Module SHALL generate a P-384 (secp384r1) key pair and return private and public keys in PEM format
2. WHEN two valid P-384 key pairs perform ECDH, THE Crypto_Module SHALL derive a 48-byte shared secret
3. WHEN a shared secret, salt, info, and length are provided, THE Crypto_Module SHALL derive a key of the specified length using HKDF-SHA256
4. WHEN party A uses their private key with party B's public key, THE derived shared secret SHALL equal the secret derived when party B uses their private key with party A's public key (ECDH commutativity)

### Requirement 4: Certificate Creation and Signing

**User Story:** As a CA administrator, I want to create and sign certificates, so that public keys can be bound to identities with CA endorsement.

#### Acceptance Criteria

1. WHEN a subject, public key, issuer, serial, and validity period are provided, THE PKI_Module SHALL create an unsigned certificate dictionary containing all specified fields plus computed not_before and not_after timestamps
2. WHEN an unsigned certificate and CA private key are provided, THE PKI_Module SHALL sign the canonical JSON representation of the certificate using RSA-PSS and populate the signature field
3. THE PKI_Module SHALL validate that the subject is a non-empty string of at most 256 characters
4. THE PKI_Module SHALL validate that not_before is less than not_after and that validity is between 1 day and 10 years
5. THE PKI_Module SHALL assign positive, monotonically increasing serial numbers that are unique across all issued certificates

### Requirement 5: Certificate Chain Validation

**User Story:** As a system operator, I want certificate validation against the CA and CRL, so that expired, revoked, or forged certificates are reliably rejected.

#### Acceptance Criteria

1. WHEN a valid, non-expired, non-revoked certificate is verified against the CA public key, THE PKI_Module SHALL return (True, "Valid")
2. WHEN a certificate's not_after timestamp is in the past, THE PKI_Module SHALL return (False, "Expired")
3. WHEN a certificate's not_before timestamp is in the future, THE PKI_Module SHALL return (False, "Not yet valid")
4. WHEN a certificate's serial number appears in the CRL, THE PKI_Module SHALL return (False, "Revoked")
5. WHEN a certificate's signature does not match the CA public key, THE PKI_Module SHALL return (False, "Invalid signature")
6. THE PKI_Module SHALL check validity in the order: temporal validity, revocation status, signature verification

### Requirement 6: Canonical JSON Serialization

**User Story:** As a developer, I want deterministic JSON serialization, so that cryptographic signatures over JSON structures are reproducible and verifiable.

#### Acceptance Criteria

1. THE PKI_Module SHALL serialize dictionaries with lexicographically sorted keys at all nesting levels
2. THE PKI_Module SHALL produce output with no extraneous whitespace (compact separators)
3. THE PKI_Module SHALL use ASCII-safe encoding for all output
4. WHEN two dictionaries contain identical key-value pairs in different insertion orders, THE PKI_Module SHALL produce identical canonical JSON output
5. WHEN a certificate is serialized and then deserialized, THE resulting dictionary SHALL be equivalent to the original certificate dictionary (round-trip)

### Requirement 7: Key Generation and Encrypted Storage

**User Story:** As a user, I want my private keys encrypted at rest with a password, so that key material remains confidential even if storage is compromised.

#### Acceptance Criteria

1. WHEN a key pair is generated with a name and password, THE Key_Manager SHALL store the private key encrypted with PBKDF2-SHA256 (minimum 100,000 iterations) + AES-256-GCM and store the public key as unencrypted PEM
2. WHEN a private key is loaded with the correct password, THE Key_Manager SHALL decrypt and return the original private key PEM bytes
3. IF a private key is loaded with an incorrect password, THEN THE Key_Manager SHALL raise a ValueError
4. IF a key generation is attempted with a name that already exists, THEN THE Key_Manager SHALL raise a FileExistsError
5. IF a key is loaded that does not exist in the keystore, THEN THE Key_Manager SHALL raise a FileNotFoundError
6. THE Key_Manager SHALL ensure that plaintext private key material never appears in the stored file content
7. WHEN listing keys, THE Key_Manager SHALL return the names of all key pairs in the keystore
8. WHEN a key is deleted, THE Key_Manager SHALL remove both private and public key files from the keystore

### Requirement 8: Certificate Authority Operations

**User Story:** As a PKI administrator, I want to initialize a CA, issue certificates, and manage revocation, so that the PKI lifecycle is fully operational.

#### Acceptance Criteria

1. WHEN the CA is initialized, THE Certificate_Authority SHALL generate a CA RSA-4096 key pair, create a self-signed CA certificate, initialize an empty CRL, and create a serial counter starting at 1000
2. WHEN a certificate is issued, THE Certificate_Authority SHALL sign the certificate with the CA private key after verifying the CA password and increment the serial counter
3. WHEN a certificate is revoked by serial number, THE Certificate_Authority SHALL add the serial to the CRL and persist the updated CRL
4. IF the CA has not been initialized, THEN THE Certificate_Authority SHALL raise a RuntimeError for any issuance or revocation operation
5. IF an incorrect CA password is provided, THEN THE Certificate_Authority SHALL raise a ValueError
6. IF a serial number not found in issued certificates is provided for revocation, THEN THE Certificate_Authority SHALL raise a ValueError

### Requirement 9: File and Message Signing

**User Story:** As a user (e.g., a lawyer signing legal documents), I want to create detached digital signatures, so that document authenticity and non-repudiation are established.

#### Acceptance Criteria

1. WHEN a file is signed, THE Signature_Engine SHALL compute the SHA-256 hash of the file contents, sign the hash with RSA-PSS, and return a JSON-encoded detached signature containing the signature, signer certificate, timestamp, and original filename
2. WHEN an in-memory message is signed, THE Signature_Engine SHALL produce the same JSON signature structure as file signing
3. THE Signature_Engine SHALL not modify the original file during signing
4. THE Signature_Engine SHALL log all signing operations with component name, event type, result, and subject information
5. IF the file to be signed does not exist, THEN THE Signature_Engine SHALL raise a FileNotFoundError

### Requirement 10: Signature Verification

**User Story:** As a user, I want to verify digital signatures against the certificate chain and CRL, so that I can trust document authenticity and detect tampering or revocation.

#### Acceptance Criteria

1. WHEN a valid signature is verified against the original file, valid signer certificate, and CA certificate, THE Signature_Engine SHALL return (True, "Valid")
2. WHEN a signature is verified against a modified file, THE Signature_Engine SHALL return (False, reason) indicating signature mismatch
3. WHEN verification is performed with an expired signer certificate, THE Signature_Engine SHALL return (False, "Expired")
4. WHEN verification is performed with a revoked signer certificate, THE Signature_Engine SHALL return (False, "Revoked")
5. THE Signature_Engine SHALL validate the certificate chain before verifying the file signature, in the order: certificate validation then signature verification

### Requirement 11: Hybrid Encryption with Forward Secrecy

**User Story:** As a user (e.g., a financial institution exchanging sensitive data), I want hybrid encryption with ephemeral keys, so that message confidentiality is maintained with forward secrecy.

#### Acceptance Criteria

1. WHEN a message is encrypted for a recipient, THE Encryption_Engine SHALL generate an ephemeral ECDH P-384 key pair, derive a shared secret via ECDH, derive an AES-256 key via HKDF-SHA256, and encrypt the plaintext with AES-256-GCM
2. WHEN a message is encrypted, THE Encryption_Engine SHALL return a dictionary containing the ephemeral public key, IV, authentication tag, ciphertext, replay protection nonce, and timestamp — all base64-encoded
3. WHEN an encrypted message is decrypted with the recipient's private key, THE Encryption_Engine SHALL recover the original plaintext
4. WHEN a message is encrypted, THE Encryption_Engine SHALL delete the ephemeral private key and shared secret from memory after use
5. WHEN the same plaintext is encrypted twice for the same recipient, THE Encryption_Engine SHALL produce different ephemeral public keys, IVs, and nonces each time
6. IF the recipient's certificate contains a non-ECC public key, THEN THE Encryption_Engine SHALL reject the operation with a descriptive error

### Requirement 12: File Encryption and Decryption

**User Story:** As a user, I want to encrypt and decrypt files, so that sensitive file contents are protected in transit and at rest.

#### Acceptance Criteria

1. WHEN a file is encrypted, THE Encryption_Engine SHALL read the file contents, encrypt using hybrid encryption, and write the encrypted JSON to an output file with .enc extension
2. WHEN an encrypted file is decrypted, THE Encryption_Engine SHALL read the encrypted JSON, decrypt using the recipient's private key, and write the plaintext to the output file
3. WHEN decrypting a file, THE Encryption_Engine SHALL produce output identical to the original file content

### Requirement 13: Replay Protection

**User Story:** As a system operator, I want replay protection for encrypted messages, so that captured messages cannot be reused by attackers.

#### Acceptance Criteria

1. WHEN a fresh nonce with a valid timestamp is checked, THE Replay_Protector SHALL return (True, "Accepted") and record the nonce
2. WHEN a previously-seen nonce is checked again within the time window, THE Replay_Protector SHALL return (False, "Replay detected")
3. WHEN a nonce with a timestamp older than the configured window (default 60 seconds) is checked, THE Replay_Protector SHALL return (False, "Timestamp expired")
4. WHEN a nonce with a timestamp more than 5 seconds in the future is checked, THE Replay_Protector SHALL return (False, "Timestamp in future")
5. THE Replay_Protector SHALL automatically evict nonces older than the time window to prevent unbounded memory growth
6. THE Replay_Protector SHALL be thread-safe for concurrent nonce checks
7. THE Replay_Protector SHALL generate nonces using a CSPRNG producing exactly 16 bytes

### Requirement 14: Structured Security Logging

**User Story:** As a security auditor, I want structured, machine-parseable logs of all security operations, so that incidents can be investigated and compliance verified.

#### Acceptance Criteria

1. THE Logger SHALL emit log entries in JSON format containing timestamp, component, event, result, and optional details
2. THE Logger SHALL never include private key material, passwords, or derived keys in log output
3. WHEN a security event occurs, THE Logger SHALL record the event with component name, operation type, and outcome (success, failure, or error)
4. THE Logger SHALL support configurable log levels and output destinations (file or stdout)

### Requirement 15: CLI Interface

**User Story:** As an end user, I want a command-line interface for all PKI operations, so that I can perform key generation, signing, verification, encryption, decryption, and certificate management from the terminal.

#### Acceptance Criteria

1. WHEN the user runs the `init-ca` command with a name and password, THE CLI SHALL initialize the Certificate Authority
2. WHEN the user runs the `keygen` command with a name, type, size, and password, THE CLI SHALL generate and store a key pair
3. WHEN the user runs the `issue-cert` command with subject, public key path, validity days, and CA password, THE CLI SHALL issue a signed certificate
4. WHEN the user runs the `sign` command with a file path, key name, and password, THE CLI SHALL produce a detached signature file with .sig extension
5. WHEN the user runs the `verify` command with a file path and signature path, THE CLI SHALL output whether the signature is valid or invalid with a reason
6. WHEN the user runs the `encrypt` command with a file path and recipient certificate, THE CLI SHALL produce an encrypted file with .enc extension
7. WHEN the user runs the `decrypt` command with an encrypted file path, key name, and password, THE CLI SHALL produce the decrypted file
8. WHEN the user runs the `revoke-cert` command with a serial number and CA password, THE CLI SHALL revoke the specified certificate
9. IF any CLI command fails, THEN THE CLI SHALL display a descriptive error message and exit with a non-zero status code

### Requirement 16: Data Schema Validation

**User Story:** As a developer, I want strict schema validation for certificates, signatures, and encrypted messages, so that malformed data is rejected early with clear error messages.

#### Acceptance Criteria

1. WHEN a certificate is processed, THE System SHALL validate that the serial is a positive integer, subject is non-empty (max 256 chars), key_type is "rsa" or "ecc", public_key is valid PEM, and signature is valid base64
2. WHEN a detached signature is processed, THE System SHALL validate that version equals 1, algorithm is "RSA-PSS-SHA256", signature is valid base64, signer_cert is a valid certificate dictionary, and timestamp is not in the future
3. WHEN an encrypted message is processed, THE System SHALL validate that iv_b64 decodes to exactly 12 bytes, tag_b64 decodes to exactly 16 bytes, nonce_b64 decodes to exactly 16 bytes, and ephemeral_pub_b64 decodes to a valid ECC P-384 public key
4. WHEN a key storage file is processed, THE System SHALL validate that iterations is at least 100,000, salt_b64 decodes to exactly 16 bytes, iv_b64 decodes to exactly 12 bytes, and tag_b64 decodes to exactly 16 bytes

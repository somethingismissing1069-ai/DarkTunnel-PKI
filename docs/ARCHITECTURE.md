# Architecture

## System Overview

SecureVault PKI is a modular cryptographic toolkit built in Python following a strict layered architecture. Each layer depends only on the layer directly below it, enabling independent testing, auditing, and extension. The system uses the `cryptography` library as its sole cryptographic provider — no custom crypto implementations.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                              │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      securevault_cli.py                            │  │
│  │         CLI argument parsing, user interaction, output             │  │
│  └──────────┬──────────────┬──────────────┬──────────────┬───────────┘  │
├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│             │   APPLICATION LAYER          │              │              │
│             ▼                              ▼              │              │
│  ┌─────────────────────┐       ┌────────────────────┐    │              │
│  │ signature_engine.py │       │ encryption_engine  │    │              │
│  │ Sign/Verify Files   │       │ Hybrid Encrypt/    │    │              │
│  │ & Messages          │       │ Decrypt            │    │              │
│  └──┬──────┬──────┬────┘       └──┬─────┬─────┬────┘    │              │
├─────┼──────┼──────┼───────────────┼─────┼─────┼─────────┼──────────────┤
│     │      │  DOMAIN LAYER        │     │     │         │              │
│     │      ▼                      │     │     ▼         ▼              │
│     │  ┌───────────────┐          │     │  ┌─────────────────────┐    │
│     │  │ key_manager   │◄─────────┼─────┘  │ replay_protection   │    │
│     │  │ Key lifecycle │          │        │ Nonce cache &       │    │
│     │  │ & storage     │          │        │ timestamps          │    │
│     │  └──────┬────────┘          │        └──────────┬──────────┘    │
│     │         │                   │                   │               │
│     ▼         │      ┌────────────┘                   │               │
│  ┌────────────┼──────┼────────────────────────────────┼───────────┐   │
│  │            ▼      ▼            certificate_authority             │   │
│  │       CA init, cert issuance, CRL management                    │   │
│  └──────────┬─────────┬──────────────────────────────┬─────────────┘   │
├─────────────┼─────────┼──────────────────────────────┼──────────────────┤
│             │    INFRASTRUCTURE LAYER                 │                  │
│             ▼                                        ▼                  │
│  ┌─────────────────────┐  ┌──────────────┐  ┌───────────────────┐     │
│  │   crypto_utils.py   │  │ pki_utils.py │  │  logging_utils.py │     │
│  │ AES-GCM, RSA, ECC   │  │ Cert structs │  │  Structured JSON  │     │
│  │ ECDH, HKDF, B64     │  │ Canon JSON   │  │  security logging │     │
│  │                     │  │ Validation   │  │                   │     │
│  └─────────────────────┘  └──────────────┘  └───────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

| Module | Layer | Responsibility | Dependencies |
|--------|-------|---------------|-------------|
| `securevault_cli.py` | Presentation | CLI parsing, command dispatch, error formatting | signature_engine, encryption_engine, certificate_authority, key_manager |
| `signature_engine.py` | Application | File/message signing and verification workflows | pki_utils, crypto_utils, key_manager, logging_utils |
| `encryption_engine.py` | Application | Hybrid encryption/decryption with forward secrecy | crypto_utils, pki_utils, replay_protection, logging_utils |
| `certificate_authority.py` | Domain | CA initialization, cert issuance, CRL management | pki_utils, key_manager, crypto_utils, logging_utils |
| `key_manager.py` | Domain | Key generation, encrypted storage, keystore CRUD | crypto_utils, logging_utils |
| `replay_protection.py` | Domain | Thread-safe nonce tracking, timestamp validation | logging_utils |
| `pki_utils.py` | Infrastructure | Certificate structures, canonical JSON, chain validation | crypto_utils |
| `crypto_utils.py` | Infrastructure | All cryptographic primitives (AES, RSA, ECC, HKDF) | cryptography library |
| `logging_utils.py` | Infrastructure | JSON log format, audit events, no key leakage | Python logging stdlib |
| `schema_validation.py` | Infrastructure | Input validation for all data structures | None |

## Data Flow

### Signing Flow

```
User → CLI → key_manager (decrypt private key)
                → signature_engine
                    → Read file contents
                    → SHA-256 hash
                    → crypto_utils.rsa_sign(hash, private_key)
                    → Package JSON {signature, cert, timestamp, filename}
                    → logging_utils.log_event("sign_file", "success")
                → Write .sig file
```

### Verification Flow

```
User → CLI → signature_engine
                → pki_utils.verify_certificate(signer_cert, ca_pub_key, crl)
                    → Check temporal validity (not_before <= now <= not_after)
                    → Check CRL (serial not in revoked set)
                    → crypto_utils.rsa_verify(canonical_cert, ca_signature)
                → Read file, compute SHA-256 hash
                → crypto_utils.rsa_verify(hash, signature, signer_pub_key)
                → Return (is_valid, reason)
```

### Encryption Flow

```
User → CLI → encryption_engine
                → crypto_utils.ecdh_keygen() → ephemeral key pair
                → Extract recipient public key from certificate
                → crypto_utils.ecdh_derive_shared_secret(ephemeral_priv, recipient_pub)
                → crypto_utils.hkdf_expand(shared_secret) → AES-256 key
                → crypto_utils.aes_encrypt(plaintext, aes_key)
                → Generate nonce + timestamp (replay protection)
                → Delete ephemeral private key + shared secret
                → Return encrypted message dict
```

### Decryption Flow

```
User → CLI → key_manager (decrypt private key)
                → encryption_engine
                    → replay_protection.check_nonce(nonce, timestamp)
                    → Decode ephemeral public key from message
                    → crypto_utils.ecdh_derive_shared_secret(recipient_priv, ephemeral_pub)
                    → crypto_utils.hkdf_expand(shared_secret) → AES-256 key
                    → crypto_utils.aes_decrypt(ciphertext, iv, tag, aes_key)
                    → Return plaintext
```

## Certificate Lifecycle

```
                    ┌──────────────┐
                    │   CA Init    │
                    │ (RSA-4096)   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Self-Signed │
                    │  CA Cert     │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │  Issue     │ │  Issue     │ │  Issue     │
       │  Cert #1   │ │  Cert #2   │ │  Cert #N   │
       │  (serial   │ │  (serial   │ │  (serial   │
       │   1000)    │ │   1001)    │ │   100N)    │
       └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
             │               │               │
             ▼               ▼               ▼
       ┌──────────┐    ┌──────────┐    ┌──────────┐
       │  Active  │    │ Revoked  │    │ Expired  │
       │          │    │ (in CRL) │    │          │
       └──────────┘    └──────────┘    └──────────┘
```

### Certificate States

1. **Created** — Unsigned certificate dict with subject, public key, issuer, serial, validity
2. **Issued** — Signed by CA (RSA-PSS signature over canonical JSON)
3. **Active** — Within validity period, not in CRL, signature valid
4. **Revoked** — Serial added to CRL; permanently invalidated
5. **Expired** — `not_after` timestamp has passed; no longer accepted

### Validation Order

Certificates are validated in a strict order to prevent unnecessary computation:

1. **Temporal validity** — Is the certificate within its valid time range?
2. **Revocation status** — Is the serial number in the CRL?
3. **Signature verification** — Does the CA signature match?

## Storage Layout

```
~/.securevault/
├── keys/
│   ├── alice.priv       # PBKDF2+AES-256-GCM encrypted private key (JSON)
│   ├── alice.pub        # Public key (PEM, unencrypted)
│   ├── bob.priv
│   └── bob.pub
└── ca/
    ├── ca.priv          # CA private key (encrypted)
    ├── ca.pub           # CA public key (PEM)
    ├── ca_cert.json     # Self-signed CA certificate
    ├── crl.json         # Certificate Revocation List
    └── serial.txt       # Next serial number counter
```

## Design Principles

1. **Layered Dependencies** — Higher layers depend only on lower layers; never upward
2. **Single Crypto Provider** — All crypto via `cryptography` library; no custom implementations
3. **Defense in Depth** — Multiple validation layers (signature + timestamp + nonce)
4. **Fail Secure** — All verification failures return explicit rejection
5. **No Plaintext Keys on Disk** — Private keys always encrypted at rest
6. **Ephemeral Key Deletion** — Forward secrecy keys deleted immediately after use
7. **Structured Audit Logging** — All security events logged; key material never logged

# Cryptographic Primitives

## Overview

This document catalogs all cryptographic algorithms and primitives used in SecureVault PKI, including their parameters, justification, and role within the system.

## Primitives Summary

| Algorithm | Purpose | Parameters | Module |
|-----------|---------|-----------|--------|
| AES-256-GCM | Authenticated symmetric encryption | Key: 256 bits, IV: 96 bits, Tag: 128 bits | `crypto_utils` |
| RSA-4096 | Key pairs for digital signatures and CA operations | Key: 4096 bits, Exponent: 65537 | `crypto_utils` |
| RSA-PSS | Digital signature scheme | Hash: SHA-256, Salt: max length, Padding: PSS | `crypto_utils` |
| ECC P-384 | Key pairs for ECDH key agreement | Curve: secp384r1, Key: 384 bits | `crypto_utils` |
| ECDH | Ephemeral key agreement for hybrid encryption | Curve: P-384, Output: 48-byte shared secret | `crypto_utils` |
| HKDF-SHA256 | Key derivation from shared secrets | Hash: SHA-256, Salt: empty, Info: context-specific, Output: 32 bytes | `crypto_utils` |
| PBKDF2-SHA256 | Password-based key derivation for key storage | Hash: SHA-256, Iterations: 100,000, Salt: 128 bits, Output: 256 bits | `key_manager` |
| SHA-256 | Cryptographic hashing for signatures | Output: 256 bits (32 bytes) | `crypto_utils` (via RSA-PSS) |
| CSPRNG | Random value generation (IVs, nonces, salts, keys) | Source: `os.urandom`, Output: variable | All modules |

## Detailed Primitive Descriptions

### AES-256-GCM (Galois/Counter Mode)

**Role in system:** Encrypts all data requiring confidentiality — message encryption (hybrid scheme), private key storage, and any symmetric encryption needs.

**Parameters:**
- **Key size:** 256 bits (32 bytes) — maximum AES key length
- **IV size:** 96 bits (12 bytes) — NIST-recommended for GCM
- **Tag size:** 128 bits (16 bytes) — maximum authentication tag
- **AAD:** Optional additional authenticated data (authenticated but not encrypted)

**Properties:**
- Provides authenticated encryption (AEAD): confidentiality + integrity + authenticity
- Ciphertext is same length as plaintext (no padding)
- Any modification to ciphertext, IV, tag, or AAD causes decryption failure (InvalidTag)
- IV must be unique per (key, message) pair — collision catastrophic for GCM

**Usage locations:**
- `crypto_utils.aes_encrypt()` / `crypto_utils.aes_decrypt()` — core symmetric operations
- `key_manager.generate_keypair()` — encrypting private keys at rest
- `encryption_engine.encrypt_message()` — message payload encryption

**Justification:** GCM provides authenticated encryption in a single pass with hardware acceleration. It eliminates the need for separate MAC operations and is resistant to padding oracle attacks (unlike CBC mode).

---

### RSA-4096

**Role in system:** Generates key pairs used for digital signatures (document signing, certificate signing).

**Parameters:**
- **Key size:** 4096 bits — provides ~128-bit security level
- **Public exponent:** 65537 (0x10001) — standard choice
- **Key format:** PEM (PKCS#8 for private, SubjectPublicKeyInfo for public)

**Properties:**
- Key generation takes ~2-5 seconds (acceptable for one-time operation)
- Private key PEM size: ~3.2 KB
- Public key PEM size: ~0.8 KB
- Security equivalent: ~128-bit symmetric security

**Usage locations:**
- `crypto_utils.rsa_keygen()` — CA and user RSA key generation
- `certificate_authority.init_ca()` — CA key pair creation
- `key_manager.generate_keypair()` — user RSA key creation

**Justification:** 4096-bit RSA provides a conservative security margin for long-lived CA keys. While 2048-bit is still considered secure until 2030, 4096-bit is appropriate for keys that may protect data for decades.

---

### RSA-PSS (Probabilistic Signature Scheme)

**Role in system:** Creates and verifies digital signatures over documents, messages, and certificates.

**Parameters:**
- **Hash algorithm:** SHA-256
- **Padding:** PSS (Probabilistic Signature Scheme)
- **Salt length:** Maximum (equal to hash output length: 32 bytes)
- **Trailer field:** 0xBC (standard)

**Properties:**
- Probabilistic: different signature each time for same message (due to random salt)
- Provably secure under RSA assumption in random oracle model
- Signature size: 512 bytes (4096 bits / 8) encoded as base64 (~684 chars)
- Verification is deterministic despite randomized signing

**Usage locations:**
- `crypto_utils.rsa_sign()` — creates RSA-PSS signature
- `crypto_utils.rsa_verify()` — verifies RSA-PSS signature
- `pki_utils.sign_certificate()` — CA signs certificates
- `signature_engine.sign_file()` — signs document hashes

**Justification:** PSS has a tight security proof (unlike PKCS#1 v1.5) and is resistant to Bleichenbacher-style attacks. The randomized nature prevents signature comparison attacks.

---

### ECC P-384 (secp384r1)

**Role in system:** Generates key pairs for ECDH key agreement in the hybrid encryption scheme.

**Parameters:**
- **Curve:** NIST P-384 (secp384r1)
- **Key size:** 384 bits (private scalar), 768 bits (public point)
- **Field:** Prime field GF(p) where p is a 384-bit prime
- **Cofactor:** 1

**Properties:**
- Provides ~192-bit security level
- Key generation: ~5-20 ms
- Private key PEM size: ~288 bytes
- Public key PEM size: ~215 bytes
- Smaller keys than RSA with comparable security

**Usage locations:**
- `crypto_utils.ecdh_keygen()` — generates ECC key pairs
- `encryption_engine.encrypt_message()` — generates ephemeral keys
- `key_manager.generate_keypair()` — user ECC key creation

**Justification:** P-384 provides a higher security margin (~192-bit) than P-256 (~128-bit) for long-term key material. This is appropriate for encryption keys protecting sensitive data that must remain confidential for years.

---

### ECDH (Elliptic Curve Diffie-Hellman)

**Role in system:** Derives shared secrets between an ephemeral sender key and the recipient's long-term key for hybrid encryption.

**Parameters:**
- **Curve:** P-384 (secp384r1)
- **Shared secret size:** 48 bytes (384 bits) — x-coordinate of resulting EC point
- **Key agreement:** Static-ephemeral (recipient has static key, sender generates ephemeral)

**Properties:**
- Commutativity: `ECDH(A_priv, B_pub) == ECDH(B_priv, A_pub)`
- Output is not uniformly random (must be processed through KDF)
- Forward secrecy when ephemeral keys are used and deleted
- Computation: single elliptic curve point multiplication (~5-15 ms)

**Usage locations:**
- `crypto_utils.ecdh_derive_shared_secret()` — raw ECDH computation
- `encryption_engine.encrypt_message()` — sender derives shared secret
- `encryption_engine.decrypt_message()` — recipient derives same shared secret

**Justification:** ECDH enables forward secrecy through ephemeral keys. Combined with HKDF, it provides a secure and efficient mechanism for deriving per-message symmetric keys without requiring a pre-shared secret.

---

### HKDF-SHA256 (HMAC-based Key Derivation Function)

**Role in system:** Derives uniformly random symmetric keys from ECDH shared secrets.

**Parameters:**
- **Hash:** SHA-256
- **Salt:** Empty bytes `b""` (HKDF uses zero-filled hash-length salt internally)
- **Info:** `b"encryption"` (context/purpose separation)
- **Output length:** 32 bytes (256 bits for AES-256)

**Properties:**
- Two phases: Extract (concentrate entropy) + Expand (produce key material)
- Output is indistinguishable from random if input has sufficient entropy
- Deterministic: same inputs always produce same output
- Info parameter provides domain separation (different info → different keys)

**Usage locations:**
- `crypto_utils.hkdf_expand()` — derives keys from shared secrets
- `encryption_engine.encrypt_message()` — derives AES key from ECDH secret
- `encryption_engine.decrypt_message()` — re-derives same AES key

**Justification:** ECDH shared secrets are not uniformly random and should never be used directly as encryption keys. HKDF is the standard mechanism (RFC 5869) for extracting and expanding key material from Diffie-Hellman outputs.

---

### PBKDF2-SHA256 (Password-Based Key Derivation Function 2)

**Role in system:** Derives encryption keys from user passwords for protecting private key files at rest.

**Parameters:**
- **Hash:** SHA-256
- **Iterations:** 100,000 (minimum)
- **Salt:** 16 bytes (128 bits) from CSPRNG, unique per key
- **Output length:** 32 bytes (256 bits for AES-256-GCM key)

**Properties:**
- Computation cost: ~200-500 ms per derivation (intentionally slow)
- Salt prevents rainbow table attacks
- Iteration count provides tunable brute-force resistance
- Available in Python stdlib (`hashlib.pbkdf2_hmac`)

**Storage format:**
```json
{
    "algorithm": "PBKDF2-SHA256+AES-256-GCM",
    "salt_b64": "<16 bytes, base64>",
    "iterations": 100000,
    "iv_b64": "<12 bytes, base64>",
    "tag_b64": "<16 bytes, base64>",
    "encrypted_key_b64": "<encrypted private key PEM, base64>"
}
```

**Usage locations:**
- `key_manager.generate_keypair()` — derives key for encrypting private key
- `key_manager.load_private_key()` — re-derives key for decrypting private key

**Justification:** PBKDF2 is widely available (stdlib), well-understood, and provides adequate brute-force resistance for our threat model. The 100,000 iteration count balances security (~3 attempts/sec) against usability (~300ms latency).

---

### SHA-256 (Secure Hash Algorithm)

**Role in system:** Provides collision-resistant hashing for signatures (implicitly through RSA-PSS) and file integrity verification.

**Parameters:**
- **Output size:** 256 bits (32 bytes)
- **Block size:** 512 bits
- **Security:** 128-bit collision resistance, 256-bit preimage resistance

**Properties:**
- Deterministic: same input always produces same hash
- Avalanche effect: single bit change in input changes ~50% of output bits
- One-way: computationally infeasible to find input from hash

**Usage locations:**
- Implicitly used in RSA-PSS (SHA-256 as internal hash)
- Implicitly used in HKDF (HMAC-SHA-256)
- Implicitly used in PBKDF2 (HMAC-SHA-256)
- `signature_engine.sign_file()` — hashes file contents before signing

**Justification:** SHA-256 is the standard hash function for modern cryptographic protocols. It provides 128-bit collision resistance, which is adequate for all SecureVault use cases.

---

### CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)

**Role in system:** Generates all random values used throughout the system.

**Parameters:**
- **Source:** `os.urandom()` (backed by OS entropy pool)
- **Platform sources:**
  - Linux: `/dev/urandom` (getrandom syscall)
  - macOS: `SecRandomCopyBytes`
  - Windows: `CryptGenRandom`

**Generated values:**
| Value | Size | Usage |
|-------|------|-------|
| AES-GCM IV | 12 bytes | Unique per encryption |
| PBKDF2 salt | 16 bytes | Unique per key storage |
| Replay nonce | 16 bytes | Unique per message |
| RSA-PSS salt | 32 bytes | Random per signature (internal) |
| Ephemeral ECC key | ~48 bytes (scalar) | Unique per encryption |

**Usage locations:**
- `crypto_utils.aes_encrypt()` — IV generation
- `key_manager.generate_keypair()` — salt generation
- `replay_protection.generate_nonce()` — nonce generation
- `crypto_utils.ecdh_keygen()` — key generation (via cryptography library)

**Justification:** All random values in a cryptographic system must come from a CSPRNG. Using `os.urandom()` delegates to the OS kernel's entropy pool, which is continuously seeded from hardware sources.

## Algorithm Relationships

```
Password → [PBKDF2-SHA256] → AES-256 Key → [AES-256-GCM] → Encrypted Private Key
                                                                    ↕ (stored on disk)

Ephemeral ECC Key ─┐
                    ├── [ECDH P-384] → Shared Secret → [HKDF-SHA256] → AES-256 Key
Recipient ECC Key ──┘                                                        │
                                                                             ↓
                                                                    [AES-256-GCM]
                                                                         │
                                                                         ↓
                                                                    Ciphertext + Tag

Document → [SHA-256] → Hash → [RSA-PSS] → Signature (base64)
                                  ↑
                           CA Private Key
```

## Recommended Reading

- **RFC 5116** — An Interface and Algorithms for Authenticated Encryption (AEAD)
- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 8017** — PKCS #1: RSA Cryptography Specifications (includes PSS)
- **RFC 8018** — PKCS #5: Password-Based Cryptography Specification (PBKDF2)
- **NIST SP 800-38D** — Recommendation for Block Cipher Modes: GCM
- **NIST SP 800-56A** — Recommendation for Pair-Wise Key-Establishment Using Discrete Logarithm Cryptography (ECDH)
- **NIST SP 800-56C** — Recommendation for Key-Derivation Methods in Key-Establishment Schemes
- **NIST SP 800-132** — Recommendation for Password-Based Key Derivation
- **FIPS 186-5** — Digital Signature Standard (DSS) — includes ECDSA and RSA-PSS
- **SEC 2** — Recommended Elliptic Curve Domain Parameters (secp384r1)

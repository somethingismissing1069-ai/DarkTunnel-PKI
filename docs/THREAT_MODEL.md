# Threat Model

## Overview

This document describes the security threats that SecureVault PKI is designed to defend against, the mitigations employed, explicit security assumptions, and attack scenarios with their corresponding defenses.

## In-Scope Threats

| Threat | Description | Mitigation | Component |
|--------|-------------|-----------|-----------|
| Man-in-the-Middle (MITM) | Attacker intercepts and modifies messages between parties | Certificate chain validation ensures identity binding; RSA-PSS CA signatures prevent certificate forgery | `pki_utils`, `certificate_authority` |
| Replay Attacks | Attacker captures and re-sends a previously valid encrypted message | Nonce cache with configurable time window (60s default); timestamp validation rejects expired/future messages | `replay_protection` |
| Message Tampering | Attacker modifies ciphertext or signed data in transit | AES-256-GCM authentication tag detects any modification; RSA-PSS signatures detect document alterations | `crypto_utils`, `signature_engine` |
| Key Exposure at Rest | Attacker gains access to stored private key files | PBKDF2-SHA256 (100K iterations) + AES-256-GCM encryption of private keys; plaintext key material never written to disk | `key_manager` |
| Certificate Forgery | Attacker creates fake certificates to impersonate identities | RSA-4096 CA signature verification; only certificates signed by the trusted CA are accepted | `pki_utils`, `certificate_authority` |
| Compromised Certificate Use | Attacker uses a stolen certificate after it's been reported compromised | Certificate Revocation List (CRL) checked before every verification; revoked serials permanently rejected | `certificate_authority`, `pki_utils` |
| Timing Attacks | Attacker measures response time to infer secret values | `hmac.compare_digest()` used for all security-sensitive comparisons (constant-time) | `crypto_utils` |
| Password Brute Force | Attacker attempts to guess keystore passwords offline | PBKDF2 with 100,000 iterations introduces ~300ms per attempt; 16-byte random salt prevents precomputation | `key_manager` |
| Unauthorized Signing | Attacker signs documents without proper credentials | Private key access requires correct password; signing operations logged for audit | `key_manager`, `signature_engine`, `logging_utils` |

## Out-of-Scope Threats

The following threats are explicitly **not** addressed by SecureVault PKI:

| Threat | Reason for Exclusion |
|--------|---------------------|
| **Traffic Analysis** | SecureVault does not protect metadata (message timing, sizes, or communication patterns). A dedicated transport layer (e.g., TLS, Tor) is required. |
| **Side-Channel Attacks** | Beyond constant-time comparison, no protection against power analysis, electromagnetic emanation, cache timing, or speculative execution attacks. Hardware-level countermeasures are out of scope. |
| **Malicious CA Operator** | The CA is assumed to be trusted. A compromised CA can issue arbitrary certificates. Multi-party CA or threshold signing would mitigate this but adds significant complexity. |
| **Denial of Service (DoS)** | No rate limiting, connection management, or resource allocation controls. The system is designed for correctness, not availability under adversarial load. |
| **Physical Access Attacks** | If an attacker has physical access to the machine running SecureVault, they may extract keys from memory (cold boot attacks, DMA) or install keyloggers. |
| **Quantum Computing** | Current algorithms (RSA, ECDH) are vulnerable to quantum computers running Shor's algorithm. Post-quantum migration is a future consideration. |
| **Memory-Level Key Recovery** | Python's garbage collector may retain copies of sensitive data in memory. The `del` keyword provides best-effort cleanup but cannot guarantee complete erasure. |
| **Supply Chain Attacks** | Compromise of the `cryptography` library or its dependencies is not defended against. Dependency pinning and integrity verification are recommended. |

## Security Assumptions

SecureVault PKI's security guarantees rely on the following assumptions:

### 1. Trusted Certificate Authority

The CA private key is assumed to be held by a trustworthy operator. All security guarantees collapse if the CA is compromised, as the attacker could issue valid certificates for any identity.

**Mitigation if violated:** Revoke all certificates, re-initialize CA, re-issue all certificates to verified identities.

### 2. Cryptographically Secure Random Number Generator

All random values (IVs, nonces, salts, keys) are generated using the operating system's CSPRNG (`os.urandom`). The system assumes this source provides unpredictable, uniformly distributed random bytes.

**Depends on:** Proper OS entropy pool seeding (system boot, hardware RNG).

### 3. No Side-Channel Leakage

Beyond constant-time comparison (`hmac.compare_digest`), the system assumes that cryptographic operations do not leak information through timing, power consumption, or other observable channels.

**Note:** The `cryptography` library implements some constant-time operations internally (e.g., RSA blinding), but Python-level code may introduce timing variations.

### 4. Accurate System Clock

Replay protection and certificate validity depend on accurate timestamps. Clock skew tolerance is:
- **Replay protection:** 5 seconds future tolerance
- **Certificate validity:** Compared against `time.time()` directly

**Risk if violated:** Expired certificates may be accepted; replay window may be ineffective.

### 5. Secure Storage Medium

While private keys are encrypted at rest, the system assumes the underlying storage medium provides basic access controls. An attacker with persistent file system access could:
- Monitor for plaintext keys in memory
- Perform offline brute-force against PBKDF2-encrypted keys (mitigated by iteration count)

### 6. Correct Implementation of Underlying Libraries

SecureVault delegates all cryptographic operations to the `cryptography` library (backed by OpenSSL). The security guarantees assume correct implementation of:
- AES-256-GCM (libcrypto)
- RSA key generation and signing (libcrypto)
- ECDH key agreement (libcrypto)
- HKDF and PBKDF2 (libcrypto)

## Attack Scenarios and Defenses

### Scenario 1: Intercepted Encrypted Message

**Attack:** An attacker captures an encrypted message in transit.

**Defense:**
1. Message is encrypted with AES-256-GCM using a key derived from ephemeral ECDH
2. Without the recipient's private key, the attacker cannot derive the shared secret
3. Forward secrecy ensures that even if the recipient's long-term key is later compromised, this specific message remains secure (ephemeral key was deleted)

**Result:** Attack fails. Attacker obtains ciphertext with no path to plaintext.

### Scenario 2: Replay of Encrypted Message

**Attack:** An attacker captures a valid encrypted message and re-sends it to the recipient.

**Defense:**
1. Each message contains a unique 16-byte nonce and timestamp
2. The `ReplayProtector` records all nonces within the time window (60s)
3. On second delivery, the nonce is recognized as already-seen
4. Response: `(False, "Replay detected")`

**Result:** Replay detected and rejected.

### Scenario 3: Tampered Document with Valid Signature

**Attack:** An attacker modifies a signed document while keeping the original `.sig` file.

**Defense:**
1. Verification re-computes SHA-256 hash of the document
2. Modified document produces a different hash
3. RSA-PSS signature verification fails (signature was over the original hash)
4. Response: `(False, "Signature mismatch")`

**Result:** Tampering detected. Signature is invalid.

### Scenario 4: Forged Certificate

**Attack:** An attacker creates a certificate claiming to be "Alice" with their own public key.

**Defense:**
1. Certificate verification checks the CA signature over the canonical JSON
2. The attacker cannot produce a valid RSA-PSS signature without the CA private key
3. Without a valid CA signature, the certificate is rejected
4. Response: `(False, "Invalid signature")`

**Result:** Forged certificate rejected.

### Scenario 5: Use of Revoked Certificate

**Attack:** An attacker uses a certificate that has been reported compromised and revoked.

**Defense:**
1. The CA maintains a CRL (Certificate Revocation List)
2. Before signature/encryption verification, the CRL is checked
3. If the certificate's serial number is in the CRL, it's rejected
4. Response: `(False, "Revoked")`

**Result:** Revoked certificate cannot be used for verification.

### Scenario 6: Offline Password Attack on Keystore

**Attack:** An attacker obtains encrypted private key files and attempts to brute-force the password.

**Defense:**
1. PBKDF2-SHA256 with 100,000 iterations (~300ms per attempt on standard hardware)
2. 16-byte random salt prevents precomputed rainbow tables
3. Estimated brute-force rates:
   - 6-char lowercase password: ~308M combinations / ~3 attempts per second = ~3.3 years
   - 8-char mixed-case: ~218T combinations / ~3 attempts per second = ~2.3M years

**Result:** Strong passwords remain secure against offline attack within reasonable timeframes.

### Scenario 7: Timing Attack on Signature Verification

**Attack:** An attacker submits many signature guesses and measures response time to determine correct bytes.

**Defense:**
1. All cryptographic comparisons use `hmac.compare_digest()` (constant-time)
2. Response time does not vary based on how many bytes of the signature are correct
3. The `cryptography` library implements RSA blinding to prevent timing leakage during modular exponentiation

**Result:** Timing measurements reveal no useful information.

### Scenario 8: Expired Certificate Exploitation

**Attack:** An attacker attempts to use a certificate whose validity period has ended.

**Defense:**
1. Certificate validation checks `not_after` against current system time **first** (before signature check)
2. Expired certificates are rejected immediately regardless of signature validity
3. Response: `(False, "Expired")`

**Result:** Expired certificates cannot be used for any operations.

## Security Boundaries

```
┌─────────────────────────────────────────┐
│           TRUST BOUNDARY                 │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │     SecureVault Process         │   │
│  │                                 │   │
│  │  Trusted:                       │   │
│  │  - CA private key (in memory)   │   │
│  │  - Decrypted private keys       │   │
│  │  - Ephemeral ECDH keys          │   │
│  │  - Derived shared secrets       │   │
│  │  - AES session keys             │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │     Encrypted Storage           │   │
│  │                                 │   │
│  │  Protected:                     │   │
│  │  - .priv files (PBKDF2+AES)    │   │
│  │  - CA key (PBKDF2+AES)         │   │
│  └─────────────────────────────────┘   │
│                                         │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│           UNTRUSTED BOUNDARY            │
│                                         │
│  - Network transport                    │
│  - File system (other users)            │
│  - Certificates from unknown parties    │
│  - Signature files (may be tampered)    │
│  - Encrypted messages (may be replayed) │
│                                         │
└─────────────────────────────────────────┘
```

## Recommendations for Production Deployment

If adapting SecureVault for production use, consider the following enhancements:

1. **Upgrade to Argon2id** for password-based key derivation (memory-hard)
2. **Implement certificate pinning** to prevent MITM even with CA compromise
3. **Add OCSP support** for real-time revocation checking
4. **Use HSM** (Hardware Security Module) for CA key storage
5. **Implement rate limiting** on authentication attempts
6. **Add audit log integrity** (hash chains or append-only storage)
7. **Consider post-quantum** algorithms (ML-KEM, ML-DSA) for future-proofing
8. **Use memory-safe key handling** (mlock, madvise MADV_DONTDUMP)

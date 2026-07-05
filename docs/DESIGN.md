# Design Decisions

This document explains the rationale behind SecureVault PKI's cryptographic and architectural choices, including alternatives that were considered and the tradeoffs involved.

## Why AES-256-GCM (Not CBC or CTR)

**Decision:** Use AES-256-GCM as the sole symmetric cipher for all encryption operations.

**Rationale:**

- **Authenticated encryption in one pass** — GCM provides both confidentiality and integrity in a single operation, eliminating the need for a separate HMAC step
- **No padding oracle attacks** — Unlike CBC mode, GCM is a stream-like mode that doesn't require padding, removing an entire class of vulnerabilities
- **Hardware acceleration** — AES-GCM is hardware-accelerated (AES-NI + CLMUL) on modern CPUs, making it faster than CBC+HMAC combinations
- **Industry standard** — Used in TLS 1.3, SSH, and IPsec; extensively analyzed and widely deployed

**Alternatives Considered:**

| Mode | Pros | Cons | Why Not |
|------|------|------|---------|
| AES-CBC + HMAC | Well-understood, widely supported | Requires padding, susceptible to padding oracles, two separate operations | Additional complexity, more room for implementation errors |
| AES-CTR + HMAC | No padding needed | Two separate operations, MAC-then-encrypt vs encrypt-then-MAC decisions | Adds complexity without benefit over GCM |
| ChaCha20-Poly1305 | Constant-time without hardware, good for mobile | Less hardware acceleration on x86, less common in enterprise | AES-GCM with AES-NI is faster on server hardware |
| XChaCha20-Poly1305 | Extended nonce (192-bit) | Newer, less analysis history | Unnecessary for our use case (unique IVs via CSPRNG) |

**Key Parameters:**
- Key size: 256 bits (32 bytes) — maximum security margin
- IV size: 96 bits (12 bytes) — NIST recommended for GCM
- Tag size: 128 bits (16 bytes) — maximum authentication strength
- IV generation: CSPRNG (os.urandom)

## Why RSA-PSS (Not PKCS#1 v1.5)

**Decision:** Use RSA-PSS (Probabilistic Signature Scheme) with SHA-256 for all digital signatures.

**Rationale:**

- **Provable security** — RSA-PSS has a tight security reduction to the RSA problem in the random oracle model; PKCS#1 v1.5 does not
- **Randomized signatures** — PSS produces different signatures each time, preventing signature comparison attacks
- **No Bleichenbacher-style attacks** — PKCS#1 v1.5 signatures have a long history of implementation vulnerabilities
- **Modern standard** — Recommended by NIST SP 800-131A and required in many compliance frameworks

**Key Parameters:**
- Key size: 4096 bits — provides ~128-bit security level
- Hash: SHA-256 — strong collision resistance
- Salt length: Maximum (equal to hash length) — maximizes security margin
- Public exponent: 65537 — standard choice balancing security and performance

**Alternatives Considered:**

| Scheme | Pros | Cons | Why Not |
|--------|------|------|---------|
| PKCS#1 v1.5 | Simpler, widely compatible | Known theoretical weaknesses, deterministic | Security concerns, no provable security |
| EdDSA (Ed25519) | Fast, small keys, deterministic | Different key infrastructure, less enterprise adoption | Would require separate key type for CA operations |
| ECDSA (P-384) | Smaller signatures, faster | Requires careful nonce generation (k-value), non-deterministic | Nonce reuse catastrophe (see Sony PS3 hack) |

## Why ECDH + HKDF (Forward Secrecy)

**Decision:** Use ephemeral ECDH on P-384 with HKDF-SHA256 key derivation for hybrid encryption.

**Rationale:**

- **Forward secrecy** — Each message uses a fresh ephemeral key pair; compromising the long-term key cannot decrypt past messages
- **Efficient key agreement** — ECDH on P-384 provides ~192-bit security with much smaller keys than RSA-based key exchange
- **Clean key derivation** — HKDF provides a standards-compliant way to derive uniformly random keys from the ECDH shared secret
- **Proven design** — This is essentially the TLS 1.3 key exchange pattern (ECDHE)

**Why P-384 (not P-256 or Curve25519):**

| Curve | Security Level | Why/Why Not |
|-------|---------------|-------------|
| P-256 | ~128 bits | Sufficient but offers less margin |
| P-384 | ~192 bits | Selected: higher security margin for long-term confidentiality |
| P-521 | ~256 bits | Overkill, significantly slower |
| Curve25519 | ~128 bits | Excellent performance, but less enterprise tooling support |

**HKDF Parameters:**
- Hash: SHA-256
- Salt: Empty (uses zero-filled salt internally)
- Info: `b"encryption"` (context separation)
- Output length: 32 bytes (AES-256 key)

**Forward Secrecy Mechanism:**
1. Generate ephemeral ECDH key pair per message
2. Perform key agreement with recipient's long-term public key
3. Derive AES key via HKDF
4. Encrypt message with derived key
5. **Delete ephemeral private key and shared secret from memory**
6. Include ephemeral public key in the message for recipient to reconstruct

## Why PBKDF2 with 100,000 Iterations

**Decision:** Use PBKDF2-SHA256 with a minimum of 100,000 iterations for password-based key derivation protecting private keys at rest.

**Rationale:**

- **Brute-force resistance** — 100,000 iterations introduces ~200-500ms of computation per attempt, making offline dictionary attacks expensive
- **Standards compliance** — NIST SP 800-132 recommends PBKDF2 with iteration counts that introduce meaningful delay
- **Wide availability** — PBKDF2 is available in Python's `hashlib` standard library, avoiding additional dependencies
- **Tunable security** — Iteration count can be increased as hardware improves

**Alternatives Considered:**

| KDF | Pros | Cons | Why Not |
|-----|------|------|---------|
| Argon2id | Memory-hard, GPU-resistant, modern | Requires additional dependency (argon2-cffi) | Adds dependency; PBKDF2 is adequate for our threat model |
| bcrypt | Time-tested, memory-hard (4KB) | Fixed output size, less flexible | Less suitable for key derivation (designed for password hashing) |
| scrypt | Memory-hard, tunable | Complex parameter tuning, less adopted | Harder to configure correctly than PBKDF2 |

**Parameters:**
- Hash: SHA-256
- Salt: 16 bytes from CSPRNG (unique per key)
- Iterations: 100,000 minimum
- Output: 32 bytes (AES-256 key for encrypting the private key)

**Security Note:** PBKDF2 is not memory-hard, making it vulnerable to GPU/ASIC attacks. For a production system handling high-value keys, upgrading to Argon2id is recommended. For our educational/demonstration scope, PBKDF2 with high iteration count provides adequate protection.

## Why JSON Certificates (Not Full X.509 ASN.1)

**Decision:** Use JSON-based certificate structures with canonical serialization, rather than X.509 ASN.1/DER certificates.

**Rationale:**

- **Simplicity and auditability** — JSON is human-readable and easily inspectable; ASN.1/DER requires specialized tools to decode
- **Deterministic serialization** — Canonical JSON (sorted keys, no whitespace, ASCII) provides straightforward reproducible signing, unlike X.509 where DER encoding has subtle ordering rules
- **Educational clarity** — The certificate structure is transparent, making it easy to understand PKI concepts without X.509 complexity
- **Rapid prototyping** — JSON serialization/deserialization is trivial in Python; ASN.1 handling requires dedicated libraries

**Tradeoffs:**

| Aspect | JSON Certificates | X.509 ASN.1 |
|--------|------------------|-------------|
| Readability | Excellent | Poor (binary/base64) |
| Interoperability | Custom format | Industry standard |
| Extensions | Ad-hoc fields | Formal extension mechanism |
| Size | Larger (text-based) | Compact (binary) |
| Tooling | Standard JSON tools | Requires OpenSSL/ASN.1 parsers |
| Production use | Not recommended | Required for TLS, S/MIME, etc. |

**Known Limitations:**
- Not interoperable with TLS, S/MIME, or other X.509-based systems
- No support for certificate extensions (key usage, basic constraints, SANs)
- No support for intermediate CAs or complex chain building

## Why Detached Signatures

**Decision:** Produce detached signature files (separate `.sig` files) rather than embedding signatures in documents.

**Rationale:**

- **Document integrity** — The original file is never modified, preserving its format and hash
- **Flexibility** — Signatures can be verified independently without altering workflow
- **Multiple signatures** — Multiple parties can sign the same document without modifying it
- **Standard practice** — Tools like GPG and code signing use detached signatures

**Signature Package Contents:**
```json
{
    "version": 1,
    "algorithm": "RSA-PSS-SHA256",
    "signature": "<base64-encoded RSA-PSS signature>",
    "signer_cert": { /* full signer certificate */ },
    "timestamp": 1704067200.0,
    "filename": "contract.pdf"
}
```

## Summary of Tradeoffs

| Decision | Security Gain | Tradeoff |
|----------|--------------|----------|
| AES-256-GCM | Authenticated encryption, no padding attacks | Requires unique IVs; nonce-misuse catastrophic |
| RSA-PSS 4096-bit | Provable security, 128-bit level | Slower than ECC; large key/signature sizes |
| ECDH P-384 ephemeral | Forward secrecy per message | Per-message key generation overhead (~15ms) |
| PBKDF2 100K iter | Brute-force resistance | Not memory-hard; ~300ms per key load |
| JSON certificates | Readable, auditable, simple | Not interoperable with X.509 ecosystem |
| Detached signatures | Preserves original documents | Requires managing separate .sig files |

## References

- NIST SP 800-38D: Recommendation for GCM Mode
- NIST SP 800-131A: Transitioning Use of Cryptographic Algorithms
- NIST SP 800-132: Recommendation for Password-Based Key Derivation
- RFC 8017: PKCS #1 (RSA Cryptography, including PSS)
- RFC 5869: HKDF (HMAC-based Key Derivation Function)
- RFC 6979: Deterministic DSA/ECDSA (context for why PSS is preferred)

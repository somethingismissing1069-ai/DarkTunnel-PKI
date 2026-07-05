# Contributing to SecureVault PKI

Thank you for your interest in contributing to SecureVault PKI! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include a clear description, steps to reproduce, and expected vs. actual behavior
- For security vulnerabilities, please report privately (do not open a public issue)

### Submitting Changes

1. **Fork** the repository
2. **Create** a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Develop** your changes following the coding standards below
4. **Test** thoroughly (see Testing Requirements)
5. **Commit** with clear, descriptive messages
6. **Push** your branch and open a **Pull Request**

## Development Setup

### Prerequisites

- Python 3.11 or later
- pip (latest version)
- Git

### Installation

```bash
# Clone your fork
git clone https://github.com/your-username/DarkTunnel-PKI.git
cd DarkTunnel-PKI

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install in development mode with all dependencies
pip install -e ".[dev]"
```

### Project Structure

```
DarkTunnel-PKI/
├── securevault/              # Main package
│   ├── __init__.py
│   ├── crypto_utils.py       # Cryptographic primitives
│   ├── pki_utils.py          # Certificate structures & validation
│   ├── key_manager.py        # Key generation & encrypted storage
│   ├── certificate_authority.py  # CA operations
│   ├── signature_engine.py   # Digital signatures
│   ├── encryption_engine.py  # Hybrid encryption
│   ├── replay_protection.py  # Nonce-based replay prevention
│   ├── logging_utils.py      # Structured security logging
│   ├── schema_validation.py  # Data validation
│   └── securevault_cli.py    # CLI entry point
├── tests/                    # Test suite
│   ├── __init__.py
│   └── test_*.py
├── docs/                     # Documentation
├── pyproject.toml            # Project configuration
└── README.md
```

## Coding Standards

### Style Guide

- Follow **PEP 8** for all Python code
- Maximum line length: 100 characters
- Use 4 spaces for indentation (no tabs)

### Type Hints

All function signatures must include type annotations:

```python
def encrypt_message(plaintext: bytes, recipient_cert: dict) -> dict:
    """Encrypt a message for a specific recipient."""
    ...
```

### Docstrings

Use Google-style docstrings for all public functions, classes, and modules:

```python
def sign_file(filepath: str, private_key_pem: bytes, signer_cert: dict) -> bytes:
    """Sign a file, producing a detached signature.

    Reads the file contents, computes a SHA-256 hash, signs with RSA-PSS,
    and packages the result as a JSON signature structure.

    Args:
        filepath: Path to the file to sign.
        private_key_pem: Signer's RSA private key in PEM format.
        signer_cert: Signer's certificate dictionary.

    Returns:
        UTF-8 encoded JSON signature bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the private key is invalid.
    """
```

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Modules | `snake_case` | `crypto_utils.py` |
| Functions | `snake_case` | `aes_encrypt()` |
| Classes | `PascalCase` | `ReplayProtector` |
| Constants | `UPPER_SNAKE_CASE` | `KEYSTORE_DIR` |
| Private methods | `_leading_underscore` | `_evict_stale_nonces()` |

### Security-Specific Rules

1. **Never log private key material, passwords, or derived keys** — Use `logging_utils.log_event()` for audit events
2. **Always validate inputs** — Check key lengths, certificate fields, and data formats at entry points
3. **Use `hmac.compare_digest()`** for all security-sensitive comparisons
4. **Delete sensitive data** — Use `del` for ephemeral keys, shared secrets, and derived keys after use
5. **No custom crypto** — All cryptographic operations must use the `cryptography` library
6. **Fail secure** — Verification failures must return explicit rejection, never silently pass

### Import Order

Follow the standard Python import ordering:

```python
# 1. Standard library
import json
import os
import time
from pathlib import Path

# 2. Third-party packages
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 3. Local imports
from securevault.crypto_utils import aes_encrypt, rsa_sign
from securevault.logging_utils import log_event
```

## Testing Requirements

### Coverage Target

All contributions must maintain **85% or higher** line coverage. PRs that reduce coverage will not be merged.

### Running Tests

```bash
# Run all tests with coverage
pytest tests/ --cov=securevault

# Run with verbose output
pytest tests/ -v --tb=short

# Run specific test file
pytest tests/test_crypto_utils.py

# Generate HTML coverage report
pytest tests/ --cov=securevault --cov-report=html
open htmlcov/index.html
```

### Writing Tests

- **Unit tests** for all new functions and methods
- **Property-based tests** using `hypothesis` for core cryptographic operations
- **Integration tests** for multi-module workflows
- Place test files in `tests/` directory with `test_` prefix
- Use descriptive test names: `test_aes_decrypt_rejects_tampered_ciphertext`

### Test Structure

```python
import pytest
from hypothesis import given, strategies as st

from securevault.crypto_utils import aes_encrypt, aes_decrypt


class TestAESEncryption:
    """Tests for AES-256-GCM encryption/decryption."""

    def test_roundtrip_basic(self):
        """Encrypting and decrypting returns original plaintext."""
        key = os.urandom(32)
        plaintext = b"Hello, World!"
        iv, ciphertext, tag = aes_encrypt(plaintext, key)
        result = aes_decrypt(ciphertext, iv, tag, key)
        assert result == plaintext

    def test_invalid_key_length_raises(self):
        """Non-32-byte keys are rejected with ValueError."""
        with pytest.raises(ValueError):
            aes_encrypt(b"data", b"short_key")

    @given(plaintext=st.binary(min_size=1, max_size=10_000))
    def test_roundtrip_property(self, plaintext):
        """Property: encrypt then decrypt always recovers plaintext."""
        key = os.urandom(32)
        iv, ciphertext, tag = aes_encrypt(plaintext, key)
        assert aes_decrypt(ciphertext, iv, tag, key) == plaintext
```

### What NOT to Test

- Internal implementation details (test behavior, not implementation)
- Third-party library correctness (trust `cryptography` library)
- Performance benchmarks (separate from correctness tests)

## Pull Request Process

### Before Submitting

- [ ] All tests pass: `pytest tests/ --cov=securevault`
- [ ] Coverage is maintained at 85%+
- [ ] Code follows PEP 8 (consider running `flake8` or `ruff`)
- [ ] All functions have type hints and docstrings
- [ ] No sensitive data (keys, passwords) in committed code
- [ ] Commit messages are clear and descriptive

### PR Description Template

```markdown
## Summary
Brief description of changes.

## Changes
- Added/Modified/Removed ...

## Testing
- Describe tests added or modified
- Coverage impact

## Security Considerations
- Any security implications of the change
- Cryptographic operations added or modified
```

### Review Process

1. All PRs require at least one review
2. Security-sensitive changes require two reviews
3. CI must pass (all tests green, coverage threshold met)
4. No merge conflicts with `main`

### What We Look For in Reviews

- **Correctness** — Does the code do what it claims?
- **Security** — Are there timing leaks, missing validations, or key exposure risks?
- **Simplicity** — Is there a simpler way to achieve the same result?
- **Testing** — Are edge cases covered? Are property tests appropriate?
- **Documentation** — Are public APIs clearly documented?

## Questions?

Open a GitHub Discussion or Issue for any questions about contributing. We appreciate your help in making SecureVault PKI better!

"""Structured security logging for SecureVault PKI.

This module provides structured, machine-parseable logging for all security-relevant
operations within the SecureVault PKI system. Log entries are formatted as JSON lines
containing timestamp, component, event, result, and optional details.

Security Design:
    - NEVER log private key material, passwords, derived keys, plaintext,
      full ciphertext, nonces, or shared secrets.
    - ALWAYS log: operation type, success/failure, timestamps, component,
      non-sensitive metadata (filenames, subjects, serial numbers).
    - Details dicts are sanitized before logging to prevent accidental
      exposure of sensitive key material.

The module uses Python's standard `logging` module, which is thread-safe by default.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional


# Patterns and keywords indicating sensitive data that must never be logged
_SENSITIVE_KEYS = frozenset({
    "private_key", "private_key_pem", "password", "passphrase",
    "secret", "shared_secret", "derived_key", "aes_key",
    "plaintext", "ciphertext", "nonce", "iv", "tag",
    "salt", "key_material", "key", "priv_key", "priv",
    "encrypted_key", "decrypted_key", "raw_key",
})

# Substrings that indicate a value contains sensitive material
_SENSITIVE_VALUE_PATTERNS = (
    "-----BEGIN",
    "-----END",
    "PRIVATE KEY",
)

LOGGER_NAME = "securevault"


class _JSONFormatter(logging.Formatter):
    """Custom JSON log formatter for structured security logging.

    Produces one JSON object per log line with consistent fields:
    timestamp, component, event, result, details, and level.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON line.

        Args:
            record: The log record to format.

        Returns:
            A JSON-encoded string representing the log entry.
        """
        log_entry: dict = {
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "level": record.levelname,
        }

        # Include structured fields if present
        if hasattr(record, "component"):
            log_entry["component"] = record.component
        if hasattr(record, "event"):
            log_entry["event"] = record.event
        if hasattr(record, "result"):
            log_entry["result"] = record.result
        if hasattr(record, "details"):
            log_entry["details"] = record.details

        # Fall back to the message if no structured fields
        if not any(
            hasattr(record, attr) for attr in ("component", "event", "result")
        ):
            log_entry["message"] = record.getMessage()

        return json.dumps(log_entry, ensure_ascii=True)


def _sanitize_details(details: Optional[dict]) -> Optional[dict]:
    """Sanitize a details dictionary to prevent accidental key material exposure.

    Removes or redacts any keys that could contain sensitive cryptographic
    material such as private keys, passwords, derived keys, or raw key bytes.

    Args:
        details: The optional details dictionary to sanitize.

    Returns:
        A sanitized copy of the details dict, or None if input is None.
    """
    if details is None:
        return None

    sanitized: dict = {}
    for key, value in details.items():
        key_lower = key.lower()

        # Check if key name suggests sensitive data
        if key_lower in _SENSITIVE_KEYS:
            sanitized[key] = "[REDACTED]"
            continue

        # Check if value looks like key material
        if isinstance(value, str) and any(
            pattern in value for pattern in _SENSITIVE_VALUE_PATTERNS
        ):
            sanitized[key] = "[REDACTED]"
            continue

        # Check if value is bytes (likely raw key material)
        if isinstance(value, bytes):
            sanitized[key] = "[REDACTED]"
            continue

        # Recursively sanitize nested dicts
        if isinstance(value, dict):
            sanitized[key] = _sanitize_details(value)
            continue

        # Safe to include
        sanitized[key] = value

    return sanitized


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure Python logging with structured JSON output for SecureVault.

    Sets up the 'securevault' logger with a JSON formatter and appropriate
    handlers. Can output to stdout (default) or to a specified log file.

    Args:
        log_level: The logging level to use. One of: DEBUG, INFO, WARNING,
                   ERROR, CRITICAL. Defaults to "INFO".
        log_file: Optional path to a log file. If None, logs to stdout.

    Raises:
        ValueError: If an invalid log level is provided.
    """
    # Validate log level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicate output on re-configuration
    logger.handlers.clear()

    # Create appropriate handler
    if log_file is not None:
        handler: logging.Handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler()

    handler.setLevel(numeric_level)
    handler.setFormatter(_JSONFormatter())

    logger.addHandler(handler)

    # Prevent propagation to root logger to avoid duplicate output
    logger.propagate = False


def log_event(
    component: str, event: str, result: str, details: Optional[dict] = None
) -> None:
    """Log a security event with structured format.

    Emits a structured JSON log entry containing the component name,
    event type, result, and optional sanitized details. Sensitive fields
    in the details dict are automatically redacted.

    NEVER include in details: private keys, passwords, derived keys,
    plaintext, full ciphertext, nonces, or shared secrets.

    Safe to include in details: filenames, subjects, serial numbers,
    operation types, success/failure indicators.

    Args:
        component: The module or subsystem name (e.g., "signature_engine",
                   "certificate_authority", "key_manager").
        event: The operation being performed (e.g., "sign_file",
               "verify_cert", "issue_certificate").
        result: The outcome of the operation (e.g., "success", "failure",
                "error").
        details: Optional dictionary of additional non-sensitive metadata.
                 Automatically sanitized to prevent key material exposure.
    """
    logger = logging.getLogger(LOGGER_NAME)

    # Sanitize details to prevent accidental exposure of secrets
    safe_details = _sanitize_details(details)

    # Create log record with structured extra fields
    logger.info(
        "",
        extra={
            "component": component,
            "event": event,
            "result": result,
            "details": safe_details,
        },
    )

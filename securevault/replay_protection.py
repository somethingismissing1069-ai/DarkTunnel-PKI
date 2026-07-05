"""Replay protection module for SecureVault PKI.

Prevents replay attacks by maintaining an in-memory cache of recently seen
nonces with automatic expiry. Each encrypted message includes a unique nonce
and timestamp; this module ensures that:
  1. Messages with stale timestamps are rejected (> window seconds old)
  2. Messages with future timestamps are rejected (> 5 seconds ahead)
  3. Messages with previously-seen nonces are rejected (replay detected)
  4. Fresh, unique nonces within the time window are accepted and recorded

Thread-safe implementation using threading.Lock for concurrent access.
All nonce generation uses os.urandom (CSPRNG) to ensure unpredictability.
"""

import os
import time
from threading import Lock


class ReplayProtector:
    """Nonce-based replay attack protector with configurable time window.

    Maintains an in-memory cache mapping nonce bytes to the timestamp when
    they were received. Stale nonces are automatically evicted on each check
    to prevent unbounded memory growth.

    Attributes:
        _nonces: Dictionary mapping nonce bytes to their reception timestamp.
        _window: Time window in seconds for nonce validity (default 60).
        _lock: Threading lock for thread-safe access to the nonce cache.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        """Initialize the replay protector with a configurable time window.

        Args:
            window_seconds: How long to remember nonces in seconds (default 60).
                           Nonces older than this window are automatically evicted.
        """
        self._nonces: dict[bytes, float] = {}
        self._window: int = window_seconds
        self._lock: Lock = Lock()

    def check_nonce(self, nonce: bytes, timestamp: float = None) -> tuple[bool, str]:
        """Check if a nonce is fresh (not replayed).

        Validates that a nonce has not been seen before and that its associated
        timestamp is within the acceptable time window. This is the core defense
        against replay attacks in the encrypted messaging system.

        Validation order:
            1. Evict stale nonces (housekeeping)
            2. Check timestamp: reject if > window seconds old ("Timestamp expired")
            3. Check timestamp: reject if > 5 seconds in the future ("Timestamp in future")
            4. Check nonce: reject if already seen ("Replay detected")
            5. If all pass: record nonce and return (True, "Accepted")

        Args:
            nonce: 16-byte nonce value from the encrypted message.
            timestamp: Unix timestamp of the message. If None, uses current time.

        Returns:
            A tuple of (is_fresh, reason):
                (True, "Accepted") — fresh nonce within window
                (False, "Replay detected") — nonce already seen
                (False, "Timestamp expired") — timestamp too old (> window seconds)
                (False, "Timestamp in future") — timestamp > 5 seconds ahead
        """
        current_time: float = time.time()
        if timestamp is None:
            timestamp = current_time

        with self._lock:
            # Step 1: Evict stale nonces (housekeeping)
            self._evict_stale_nonces()

            # Step 2: Check if timestamp is too old
            age: float = current_time - timestamp
            if age > self._window:
                return (False, "Timestamp expired")

            # Step 3: Check if timestamp is too far in the future
            if age < -5.0:
                return (False, "Timestamp in future")

            # Step 4: Check if nonce has been seen before
            if nonce in self._nonces:
                return (False, "Replay detected")

            # Step 5: Record nonce and accept
            self._nonces[nonce] = timestamp
            return (True, "Accepted")

    def _evict_stale_nonces(self) -> None:
        """Remove nonces older than the time window.

        Called internally before each check to prevent unbounded memory growth.
        Removes all entries where the stored timestamp is older than
        (current_time - window_seconds).

        This method must be called while holding self._lock.
        """
        current_time: float = time.time()
        cutoff: float = current_time - self._window

        # Collect stale keys (cannot modify dict during iteration)
        stale_keys: list[bytes] = [
            k for k, ts in self._nonces.items() if ts < cutoff
        ]

        # Remove stale entries
        for key in stale_keys:
            del self._nonces[key]

    def generate_nonce(self) -> bytes:
        """Generate a cryptographically random 16-byte nonce.

        Uses os.urandom() (CSPRNG) to ensure unpredictability. Each nonce
        should be used exactly once to prevent replay attacks.

        Returns:
            A 16-byte random nonce suitable for replay protection.
        """
        return os.urandom(16)

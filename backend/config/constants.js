/**
 * DarkTunnel PKI Web - Configuration Constants
 * 
 * Defines all cryptographic parameters, rate limiting settings,
 * JWT configuration, and system-wide constants used throughout the backend.
 */

module.exports = {
  // Password hashing - bcrypt salt rounds (12 provides ~300ms per hash)
  BCRYPT_ROUNDS: 12,

  // JWT configuration
  JWT_EXPIRY: '24h',
  JWT_ALGORITHM: 'HS256',

  // AES-256-GCM symmetric encryption parameters
  AES_KEY_LENGTH: 32,       // 256 bits - key size for AES-256
  AES_IV_LENGTH: 12,        // 96 bits - NIST recommended IV length for GCM mode
  AES_TAG_LENGTH: 16,       // 128 bits - authentication tag for integrity verification

  // RSA asymmetric key sizes
  RSA_CA_KEY_SIZE: 4096,    // CA root key - 4096-bit for maximum security
  RSA_USER_KEY_SIZE: 2048,  // User keys - 2048-bit for performance balance
  RSA_NODE_KEY_SIZE: 2048,  // Relay node keys - 2048-bit

  // Replay protection parameters
  NONCE_LENGTH: 16,              // 128 bits - random nonce per message
  NONCE_WINDOW_SECONDS: 60,     // 60-second window for nonce/timestamp validation

  // Rate limiting configuration
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000,  // 15-minute window
  RATE_LIMIT_MAX_REQUESTS: 100,           // Max 100 requests per window per IP
  RATE_LIMIT_MAX_LOGIN: 5,               // Max 5 failed login attempts per window

  // Relay node identifiers (3-node onion routing path)
  RELAY_NODES: ['NodeA', 'NodeB', 'NodeC'],

  // Certificate validity period
  CERT_VALIDITY_DAYS: 365,

  // Input validation constraints
  USERNAME_MIN_LENGTH: 3,
  USERNAME_MAX_LENGTH: 30,
  PASSWORD_MIN_LENGTH: 8
};

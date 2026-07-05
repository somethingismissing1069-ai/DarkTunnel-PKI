/**
 * RSA Key Pair Generation
 *
 * Generates RSA key pairs for:
 * - CA root key (4096-bit) - maximum security for long-lived keys
 * - User keys (2048-bit) - balance of security and performance
 * - Relay node keys (2048-bit) - generated once at server startup
 *
 * Key encoding:
 * - Public key: SPKI format, PEM encoding
 * - Private key: PKCS#8 format, PEM encoding
 */
const crypto = require('crypto');

/**
 * Generate an RSA key pair with the specified modulus length.
 *
 * @param {number} [modulusLength=2048] - The RSA key size in bits (2048 or 4096)
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded key pair
 * @throws {Error} If modulusLength is not a positive integer
 */
function generateKeyPair(modulusLength = 2048) {
  if (!Number.isInteger(modulusLength) || modulusLength < 1024) {
    throw new Error('Modulus length must be an integer >= 1024');
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return { publicKey, privateKey };
}

/**
 * Generate a 4096-bit RSA key pair for the Certificate Authority.
 * Higher key size provides maximum security for the long-lived trust anchor.
 *
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded CA key pair
 */
function generateCAKeyPair() {
  return generateKeyPair(4096);
}

/**
 * Generate a 2048-bit RSA key pair for relay nodes.
 * Generated once at server startup for each relay node.
 *
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded node key pair
 */
function generateNodeKeyPair() {
  return generateKeyPair(2048);
}

/**
 * Generate a 2048-bit RSA key pair for users.
 * Balances security and registration speed for end users.
 *
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded user key pair
 */
function generateUserKeyPair() {
  return generateKeyPair(2048);
}

module.exports = {
  generateKeyPair,
  generateCAKeyPair,
  generateNodeKeyPair,
  generateUserKeyPair,
};

/**
 * RSA-OAEP Key Wrapping/Unwrapping
 *
 * Used to wrap (encrypt) AES session keys with relay node public keys.
 * Each onion layer has its AES key wrapped with a different node's RSA key.
 *
 * Why RSA-OAEP (not PKCS#1 v1.5):
 * - Provably secure under RSA assumption
 * - Resistant to Bleichenbacher/padding oracle attacks
 * - SHA-256 for both hash and MGF1
 */
const crypto = require('crypto');

/**
 * Wrap (encrypt) an AES key using RSA-OAEP with SHA-256.
 *
 * @param {Buffer} aesKey - 32-byte AES key to wrap
 * @param {string} publicKeyPem - PEM-encoded RSA public key
 * @returns {Buffer} RSA-OAEP encrypted (wrapped) AES key
 * @throws {Error} If aesKey is not 32 bytes or publicKeyPem is invalid
 */
function wrapKey(aesKey, publicKeyPem) {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== 32) {
    throw new Error('AES key must be a 32-byte Buffer');
  }
  if (!publicKeyPem || typeof publicKeyPem !== 'string') {
    throw new Error('Public key must be a PEM-encoded string');
  }

  return crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey
  );
}

/**
 * Unwrap (decrypt) an AES key using RSA-OAEP with SHA-256.
 *
 * @param {Buffer} wrappedKey - RSA-OAEP encrypted AES key
 * @param {string} privateKeyPem - PEM-encoded RSA private key
 * @returns {Buffer} Decrypted 32-byte AES key
 * @throws {Error} If unwrapping fails (wrong key or tampered data)
 */
function unwrapKey(wrappedKey, privateKeyPem) {
  if (!Buffer.isBuffer(wrappedKey)) {
    throw new Error('Wrapped key must be a Buffer');
  }
  if (!privateKeyPem || typeof privateKeyPem !== 'string') {
    throw new Error('Private key must be a PEM-encoded string');
  }

  return crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    wrappedKey
  );
}

module.exports = { wrapKey, unwrapKey };

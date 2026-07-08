/**
 * RSA-PSS Digital Signatures
 *
 * Used for:
 * - Users signing messages (non-repudiation)
 * - CA signing certificates (identity binding)
 *
 * Why RSA-PSS (not PKCS#1 v1.5):
 * - Has a tight security proof in the random oracle model
 * - Probabilistic: different signature each time
 * - Resistant to various forgery attacks
 *
 * Parameters:
 * - Hash: SHA-256
 * - Salt length: Maximum (32 bytes for SHA-256)
 */
const crypto = require('crypto');

/**
 * Sign data using RSA-PSS with SHA-256.
 *
 * @param {string|Buffer} data - The data to sign
 * @param {string} privateKeyPem - PEM-encoded RSA private key
 * @returns {Buffer} RSA-PSS signature
 * @throws {Error} If data or privateKeyPem is invalid
 */
function sign(data, privateKeyPem) {
  if (data === null || data === undefined) {
    throw new Error('Data to sign must not be null or undefined');
  }
  if (!privateKeyPem || typeof privateKeyPem !== 'string') {
    throw new Error('Private key must be a PEM-encoded string');
  }

  const signer = crypto.createSign('SHA256');
  signer.update(typeof data === 'string' ? data : data.toString('utf-8'));
  signer.end();

  return signer.sign({
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
  });
}

/**
 * Verify an RSA-PSS signature with SHA-256.
 *
 * @param {string|Buffer} data - The original data that was signed
 * @param {Buffer} signature - The RSA-PSS signature to verify
 * @param {string} publicKeyPem - PEM-encoded RSA public key
 * @returns {boolean} True if signature is valid, false otherwise
 * @throws {Error} If parameters are invalid
 */
function verify(data, signature, publicKeyPem) {
  if (data === null || data === undefined) {
    throw new Error('Data to verify must not be null or undefined');
  }
  if (!Buffer.isBuffer(signature)) {
    throw new Error('Signature must be a Buffer');
  }
  if (!publicKeyPem || typeof publicKeyPem !== 'string') {
    throw new Error('Public key must be a PEM-encoded string');
  }

  const verifier = crypto.createVerify('SHA256');
  verifier.update(typeof data === 'string' ? data : data.toString('utf-8'));
  verifier.end();

  return verifier.verify(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
    },
    signature
  );
}

module.exports = { sign, verify };

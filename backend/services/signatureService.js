/**
 * DarkTunnel PKI Web - Signature Service
 * 
 * Provides high-level message signing and verification using RSA-PSS.
 * Wraps the crypto/rsaPss module for use by other services.
 * 
 * Used for:
 * - Users signing messages before onion wrapping (non-repudiation)
 * - Verifying message signatures after onion unwrapping
 */

const rsaPss = require('../crypto/rsaPss');

/**
 * Sign plaintext data with an RSA private key using RSA-PSS (SHA-256).
 * 
 * @param {string} plaintext - The message text to sign
 * @param {string} privateKeyPem - PEM-encoded RSA private key
 * @returns {Buffer} RSA-PSS digital signature
 */
function sign(plaintext, privateKeyPem) {
  return rsaPss.sign(plaintext, privateKeyPem);
}

/**
 * Verify an RSA-PSS signature against the original plaintext.
 * 
 * @param {string} plaintext - The original message text
 * @param {Buffer} signature - The RSA-PSS signature to verify
 * @param {string} publicKeyPem - PEM-encoded RSA public key
 * @returns {boolean} True if signature is valid
 */
function verify(plaintext, signature, publicKeyPem) {
  return rsaPss.verify(plaintext, signature, publicKeyPem);
}

module.exports = { sign, verify };

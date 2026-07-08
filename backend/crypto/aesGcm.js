/**
 * AES-256-GCM Authenticated Encryption
 *
 * Provides symmetric encryption with integrity protection.
 * Used for encrypting message data at each onion routing layer.
 *
 * Parameters:
 * - Key: 32 bytes (256 bits)
 * - IV: 12 bytes (96 bits) - NIST recommended for GCM
 * - Tag: 16 bytes (128 bits) - authentication tag
 *
 * Why AES-256-GCM:
 * - Authenticated encryption (confidentiality + integrity in one pass)
 * - Hardware-accelerated on modern CPUs (AES-NI)
 * - Tampered ciphertext is detected via auth tag
 */
const crypto = require('crypto');

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * @param {Buffer} plaintext - The data to encrypt
 * @param {Buffer} key - 32-byte (256-bit) encryption key
 * @returns {{ ciphertext: Buffer, iv: Buffer, tag: Buffer }} Encrypted output
 * @throws {Error} If key is not 32 bytes or plaintext is not a Buffer
 */
function encrypt(plaintext, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('Key must be a 32-byte Buffer');
  }
  if (!Buffer.isBuffer(plaintext)) {
    throw new Error('Plaintext must be a Buffer');
  }

  // 12-byte IV is the NIST recommended length for GCM mode
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16-byte authentication tag

  return { ciphertext: encrypted, iv, tag };
}

/**
 * Decrypt ciphertext using AES-256-GCM.
 *
 * @param {Buffer} ciphertext - The encrypted data
 * @param {Buffer} key - 32-byte (256-bit) encryption key
 * @param {Buffer} iv - 12-byte initialization vector used during encryption
 * @param {Buffer} tag - 16-byte authentication tag from encryption
 * @returns {Buffer} Decrypted plaintext
 * @throws {Error} If authentication tag verification fails (tampered data)
 */
function decrypt(ciphertext, key, iv, tag) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('Key must be a 32-byte Buffer');
  }
  if (!Buffer.isBuffer(iv) || iv.length !== 12) {
    throw new Error('IV must be a 12-byte Buffer');
  }
  if (!Buffer.isBuffer(tag) || tag.length !== 16) {
    throw new Error('Tag must be a 16-byte Buffer');
  }
  if (!Buffer.isBuffer(ciphertext)) {
    throw new Error('Ciphertext must be a Buffer');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted;
}

module.exports = { encrypt, decrypt };

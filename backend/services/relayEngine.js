/**
 * DarkTunnel PKI Web - Relay Engine (Onion Packet Processing)
 * 
 * Simulates the 3-node relay network that processes onion packets:
 * 1. Validate nonce (replay protection)
 * 2. Validate timestamp (within acceptable window)
 * 3. Process Node A: unwrap key, decrypt outer layer
 * 4. Process Node B: unwrap key, decrypt middle layer
 * 5. Process Node C: unwrap key, decrypt inner layer
 * 6. Parse final payload and verify sender's signature
 * 
 * Each relay node:
 * - Uses its RSA private key to unwrap the AES session key
 * - Uses the AES key to decrypt one encryption layer
 * - Passes the result to the next node
 */

const aesGcm = require('../crypto/aesGcm');
const rsaOaep = require('../crypto/rsaOaep');
const signatureService = require('./signatureService');
const pkiService = require('./pkiService');
const db = require('../models/db');
const auditLogger = require('./auditLogger');
const constants = require('../config/constants');

/**
 * Process an onion packet through the 3-node relay network.
 * 
 * @param {Object} onionPacket - The encrypted onion packet
 * @param {string} onionPacket.nonce - Unique nonce for replay protection
 * @param {number} onionPacket.timestamp - Creation timestamp (ms since epoch)
 * @param {Object} onionPacket.packet - Outermost encrypted layer
 * @returns {{ plaintext: string, status: string, senderId: number }} Decrypted result
 * @throws {Error} On replay attack, timestamp mismatch, or crypto failure
 */
function processPacket(onionPacket) {
  const { nonce, timestamp, packet } = onionPacket;

  // Step 1: Replay protection - check if nonce was already seen
  _validateNonce(nonce);

  // Step 2: Timestamp validation - must be within acceptable window
  _validateTimestamp(timestamp);

  // Step 3: Get relay nodes from database (ordered A, B, C)
  const nodes = db.prepare('SELECT * FROM nodes ORDER BY id ASC').all();
  if (nodes.length < 3) {
    throw new Error('Insufficient relay nodes for packet processing');
  }

  // Step 4: Process through Node A (outermost layer)
  const layer2Data = _processNode(packet, nodes[0]);

  // Step 5: Process through Node B (middle layer)
  const layer2 = JSON.parse(layer2Data);
  const layer3Data = _processNode(layer2, nodes[1]);

  // Step 6: Process through Node C (innermost layer)
  const layer3 = JSON.parse(layer3Data);
  const payloadStr = _processNode(layer3, nodes[2]);

  // Step 7: Parse the final decrypted payload
  const payload = JSON.parse(payloadStr);
  const { message, signature, senderId, senderCertSerial } = payload;

  // Step 8: Get sender's public key for signature verification
  const sender = db.prepare('SELECT public_key, certificate FROM users WHERE id = ?').get(senderId);
  if (!sender) {
    throw new Error('Sender not found');
  }

  // Verify sender's certificate is still valid
  const senderCert = JSON.parse(sender.certificate);
  const certVerification = pkiService.verifyCertificate(senderCert);
  if (!certVerification.valid) {
    return { plaintext: null, status: 'signature-invalid', reason: 'Sender certificate invalid' };
  }

  // Step 9: Verify the message signature
  const sigBuffer = Buffer.from(signature, 'hex');
  const signatureValid = signatureService.verify(message, sigBuffer, sender.public_key);
  if (!signatureValid) {
    auditLogger.log('SIGNATURE_VERIFICATION_FAILED', { senderId, nonce }, senderId);
    return { plaintext: null, status: 'signature-invalid', reason: 'Message signature invalid' };
  }

  // Step 10: Store nonce to prevent replay
  _storeNonce(nonce);

  auditLogger.log('PACKET_PROCESSED', {
    senderId,
    nonce,
    status: 'delivered'
  }, senderId);

  return { plaintext: message, status: 'delivered', senderId };
}

/**
 * Decrypt one layer of the onion packet using a relay node's private key.
 * 
 * @param {Object} layer - Encrypted layer { wrappedKey, ciphertext, iv, tag }
 * @param {Object} node - Relay node record from database
 * @returns {string} Decrypted content (JSON string of next layer or final payload)
 * @private
 */
function _processNode(layer, node) {
  // Verify node's certificate is still valid
  const cert = JSON.parse(node.certificate);
  const verification = pkiService.verifyCertificate(cert);
  if (!verification.valid) {
    throw new Error(`Node ${node.name} certificate invalid: ${verification.reason}`);
  }

  // Unwrap the AES session key using node's RSA private key
  const wrappedKey = Buffer.from(layer.wrappedKey, 'hex');
  const aesKey = rsaOaep.unwrapKey(wrappedKey, node.private_key);

  // Decrypt the layer with AES-256-GCM
  const ciphertext = Buffer.from(layer.ciphertext, 'hex');
  const iv = Buffer.from(layer.iv, 'hex');
  const tag = Buffer.from(layer.tag, 'hex');

  const decrypted = aesGcm.decrypt(ciphertext, aesKey, iv, tag);
  return decrypted.toString('utf-8');
}

/**
 * Check that the nonce hasn't been seen within the replay window.
 * 
 * @param {string} nonce - Hex-encoded nonce to check
 * @throws {Error} If nonce was already used (replay attack detected)
 * @private
 */
function _validateNonce(nonce) {
  if (!nonce) {
    throw new Error('Missing nonce - possible replay attack');
  }

  // Clean up old nonces outside the window
  const windowStart = Date.now() - (constants.NONCE_WINDOW_SECONDS * 1000);
  db.prepare('DELETE FROM nonces WHERE timestamp < ?').run(windowStart);

  // Check if nonce exists in current window
  const existing = db.prepare('SELECT id FROM nonces WHERE nonce = ?').get(nonce);
  if (existing) {
    auditLogger.log('REPLAY_ATTACK_DETECTED', { nonce });
    throw new Error('Replay attack detected - nonce already used');
  }
}

/**
 * Validate that the packet timestamp is within the acceptable window.
 * 
 * @param {number} timestamp - Packet creation time (ms since epoch)
 * @throws {Error} If timestamp is outside the valid window
 * @private
 */
function _validateTimestamp(timestamp) {
  if (!timestamp) {
    throw new Error('Missing timestamp');
  }

  const now = Date.now();
  const diff = Math.abs(now - timestamp);
  const maxDiff = constants.NONCE_WINDOW_SECONDS * 1000;

  if (diff > maxDiff) {
    auditLogger.log('TIMESTAMP_VALIDATION_FAILED', {
      packetTimestamp: timestamp,
      serverTime: now,
      diffMs: diff
    });
    throw new Error('Packet timestamp outside acceptable window');
  }
}

/**
 * Store a nonce in the database to prevent replay within the window.
 * 
 * @param {string} nonce - Hex-encoded nonce to store
 * @private
 */
function _storeNonce(nonce) {
  db.prepare('INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)').run(nonce, Date.now());
}

module.exports = { processPacket };

/**
 * DarkTunnel PKI Web - Encryption Service (Onion Packet Creation)
 * 
 * Implements onion routing encryption:
 * 1. Sign the plaintext message with sender's private key
 * 2. Build payload: { message, signature, senderId }
 * 3. Encrypt with 3 layers (innermost to outermost):
 *    - Layer 3 (Node C): AES-encrypt payload, RSA-wrap key with NodeC public key
 *    - Layer 2 (Node B): AES-encrypt layer 3, RSA-wrap key with NodeB public key
 *    - Layer 1 (Node A): AES-encrypt layer 2, RSA-wrap key with NodeA public key
 * 4. Add nonce and timestamp for replay protection
 * 
 * All binary data (ciphertext, IV, tag, wrapped keys) encoded as hex strings
 * for JSON serialization.
 */

const crypto = require('crypto');
const aesGcm = require('../crypto/aesGcm');
const rsaOaep = require('../crypto/rsaOaep');
const signatureService = require('./signatureService');
const pkiService = require('./pkiService');
const db = require('../models/db');
const auditLogger = require('./auditLogger');
const constants = require('../config/constants');

/**
 * Create an onion-encrypted packet for a plaintext message.
 * 
 * The packet is encrypted in 3 layers (one per relay node), with each
 * layer's AES key wrapped with the respective node's RSA public key.
 * 
 * @param {string} plaintext - The message to encrypt
 * @param {string} senderPrivateKey - PEM-encoded sender's private key for signing
 * @param {number} senderCertSerial - Sender's certificate serial number
 * @param {number} senderId - Sender's user ID
 * @returns {Object} Onion packet with all encryption layers
 */
function createOnionPacket(plaintext, senderPrivateKey, senderCertSerial, senderId) {
  // Get all 3 relay nodes from database (ordered A, B, C)
  const nodes = db.prepare('SELECT * FROM nodes ORDER BY id ASC').all();
  if (nodes.length < 3) {
    throw new Error('Insufficient relay nodes for onion routing (need 3)');
  }

  // Verify each node's certificate is valid
  for (const node of nodes) {
    const cert = JSON.parse(node.certificate);
    const verification = pkiService.verifyCertificate(cert);
    if (!verification.valid) {
      throw new Error(`Relay node ${node.name} certificate invalid: ${verification.reason}`);
    }
  }

  // Step 1: Sign the plaintext with sender's private key (non-repudiation)
  const signature = signatureService.sign(plaintext, senderPrivateKey);

  // Step 2: Build the innermost payload
  const payload = JSON.stringify({
    message: plaintext,
    signature: signature.toString('hex'),
    senderId,
    senderCertSerial
  });

  // Step 3: Layer 3 - encrypt payload with Node C's key
  const layer3 = _encryptLayer(payload, nodes[2].public_key);

  // Step 4: Layer 2 - encrypt layer 3 with Node B's key
  const layer2Data = JSON.stringify(layer3);
  const layer2 = _encryptLayer(layer2Data, nodes[1].public_key);

  // Step 5: Layer 1 - encrypt layer 2 with Node A's key
  const layer1Data = JSON.stringify(layer2);
  const layer1 = _encryptLayer(layer1Data, nodes[0].public_key);

  // Step 6: Generate nonce and timestamp for replay protection
  const nonce = crypto.randomBytes(constants.NONCE_LENGTH).toString('hex');
  const timestamp = Date.now();

  // Construct the final onion packet
  const onionPacket = {
    version: 1,
    nonce,
    timestamp,
    layers: 3,
    packet: layer1
  };

  auditLogger.log('ONION_PACKET_CREATED', {
    senderId,
    nonce,
    layers: 3
  }, senderId);

  return onionPacket;
}

/**
 * Encrypt a layer with AES-256-GCM and wrap the AES key with RSA-OAEP.
 * 
 * @param {string} data - JSON string to encrypt
 * @param {string} publicKeyPem - RSA public key for key wrapping
 * @returns {Object} Encrypted layer with hex-encoded fields
 * @private
 */
function _encryptLayer(data, publicKeyPem) {
  // Generate a random 256-bit AES session key for this layer
  const aesKey = crypto.randomBytes(32);

  // Encrypt the data with AES-256-GCM
  const plainBuffer = Buffer.from(data, 'utf-8');
  const { ciphertext, iv, tag } = aesGcm.encrypt(plainBuffer, aesKey);

  // Wrap the AES key with the node's RSA public key (RSA-OAEP)
  const wrappedKey = rsaOaep.wrapKey(aesKey, publicKeyPem);

  // Return all components as hex strings for JSON serialization
  return {
    wrappedKey: wrappedKey.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

module.exports = { createOnionPacket };

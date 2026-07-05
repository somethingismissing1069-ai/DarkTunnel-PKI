/**
 * DarkTunnel PKI Web - Message Service
 * 
 * Manages the message lifecycle:
 * 1. User submits plaintext message
 * 2. Message is wrapped in onion encryption (3 layers)
 * 3. Packet is processed through relay simulation
 * 4. Signature is verified, message is delivered or marked failed
 * 5. Status tracking for message delivery
 * 
 * Each message goes through:
 * - Signing (sender's private key)
 * - Onion encryption (3 relay node public keys)
 * - Relay processing (3 decryption layers)
 * - Signature verification (sender's public key)
 */

const encryptionService = require('./encryptionService');
const relayEngine = require('./relayEngine');
const db = require('../models/db');
const auditLogger = require('./auditLogger');

/**
 * Send a message through the onion routing network.
 * 
 * @param {number} userId - Sender's user ID
 * @param {string} content - Plaintext message content
 * @returns {{ messageId: number, status: string }} Message ID and delivery status
 * @throws {Error} If user not found or encryption fails
 */
function sendMessage(userId, content) {
  // Get sender's cryptographic material
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) {
    const err = new Error('User not found');
    err.statusCode = 404;
    throw err;
  }

  const certificate = JSON.parse(user.certificate);

  // Create message record with pending status
  const msgResult = db.prepare(
    'INSERT INTO messages (sender_id, encrypted_payload, status) VALUES (?, ?, ?)'
  ).run(userId, '', 'pending');

  const messageId = msgResult.lastInsertRowid;

  try {
    // Create onion-encrypted packet
    const onionPacket = encryptionService.createOnionPacket(
      content,
      user.private_key,
      certificate.serialNumber,
      userId
    );

    // Store the encrypted payload
    db.prepare('UPDATE messages SET encrypted_payload = ? WHERE id = ?')
      .run(JSON.stringify(onionPacket), messageId);

    // Process through relay network
    const result = relayEngine.processPacket(onionPacket);

    // Update message status based on relay result
    if (result.status === 'delivered') {
      db.prepare('UPDATE messages SET status = ?, decrypted_content = ? WHERE id = ?')
        .run('delivered', result.plaintext, messageId);
    } else {
      db.prepare('UPDATE messages SET status = ? WHERE id = ?')
        .run(result.status, messageId);
    }

    auditLogger.log('MESSAGE_SENT', {
      messageId,
      status: result.status,
      senderId: userId
    }, userId);

    return { messageId, status: result.status };

  } catch (error) {
    // Mark message as failed on any error
    db.prepare('UPDATE messages SET status = ? WHERE id = ?')
      .run('failed', messageId);

    auditLogger.log('MESSAGE_FAILED', {
      messageId,
      senderId: userId,
      error: error.message
    }, userId);

    return { messageId, status: 'failed', error: error.message };
  }
}

/**
 * Get the status of a specific message.
 * Verifies ownership before returning status.
 * 
 * @param {number} messageId - Message ID to check
 * @param {number} userId - Requesting user's ID (for ownership check)
 * @returns {{ id: number, status: string, created_at: string }} Message status
 * @throws {Error} If message not found or unauthorized
 */
function getMessageStatus(messageId, userId) {
  const message = db.prepare(
    'SELECT id, sender_id, status, created_at, decrypted_content FROM messages WHERE id = ?'
  ).get(messageId);

  if (!message) {
    const err = new Error('Message not found');
    err.statusCode = 404;
    throw err;
  }

  // Verify ownership
  if (message.sender_id !== userId) {
    const err = new Error('Unauthorized - message belongs to another user');
    err.statusCode = 403;
    throw err;
  }

  return {
    id: message.id,
    status: message.status,
    created_at: message.created_at,
    decrypted_content: message.decrypted_content
  };
}

/**
 * Get all messages for a specific user.
 * 
 * @param {number} userId - User's ID
 * @returns {Array<{ id: number, status: string, created_at: string }>} User's messages
 */
function getUserMessages(userId) {
  return db.prepare(
    'SELECT id, status, created_at FROM messages WHERE sender_id = ? ORDER BY created_at DESC'
  ).all(userId);
}

module.exports = { sendMessage, getMessageStatus, getUserMessages };

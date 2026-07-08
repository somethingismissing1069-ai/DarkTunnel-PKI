/**
 * DarkTunnel PKI Web - Message Controller
 * 
 * Handles message sending, status retrieval, and listing.
 * All endpoints require JWT authentication.
 * 
 * POST /api/message/send - Send encrypted message through onion routing
 * GET  /api/message/:id  - Get message status by ID
 * GET  /api/messages     - List all user's messages
 */

const messageService = require('../services/messageService');

/**
 * POST /api/message/send
 * Send an encrypted message through the 3-node onion routing network.
 * The message is signed, encrypted in 3 layers, relayed, and verified.
 * 
 * Requires: JWT authentication
 * Body: { content: string }
 * Response 200: { success: true, data: { messageId, status } }
 */
exports.sendMessage = (req, res, next) => {
  try {
    const { content } = req.body;
    const result = messageService.sendMessage(req.user.userId, content);

    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    if (err.statusCode) {
      return res.status(err.statusCode).json({
        success: false,
        error: err.message
      });
    }
    next(err);
  }
};

/**
 * GET /api/message/:id
 * Get the delivery status of a specific message.
 * Only the message sender can view their own messages.
 * 
 * Requires: JWT authentication
 * Params: id - message ID
 * Response 200: { success: true, data: { id, status, created_at } }
 */
exports.getMessageStatus = (req, res, next) => {
  try {
    const messageId = parseInt(req.params.id, 10);
    if (isNaN(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message ID' });
    }

    const result = messageService.getMessageStatus(messageId, req.user.userId);
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    if (err.statusCode) {
      return res.status(err.statusCode).json({
        success: false,
        error: err.message
      });
    }
    next(err);
  }
};

/**
 * GET /api/messages
 * List all messages for the authenticated user.
 * Returns message IDs, statuses, and timestamps.
 * 
 * Requires: JWT authentication
 * Response 200: { success: true, data: [ { id, status, created_at } ] }
 */
exports.getUserMessages = (req, res, next) => {
  try {
    const messages = messageService.getUserMessages(req.user.userId);
    res.status(200).json({
      success: true,
      data: messages
    });
  } catch (err) {
    next(err);
  }
};

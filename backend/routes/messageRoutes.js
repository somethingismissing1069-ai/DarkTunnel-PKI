/**
 * DarkTunnel PKI Web - Message Routes
 * 
 * Defines routes for sending messages and tracking their delivery status.
 * All endpoints require JWT authentication.
 * 
 * POST /api/message/send - Send an encrypted message through onion routing
 * GET  /api/message/:id  - Get status of a specific message
 * GET  /api/messages     - List all messages for authenticated user
 */

const router = require('express').Router();
const messageController = require('../controllers/messageController');

// Send a new encrypted message through the relay network
router.post('/send', messageController.sendMessage);

// Get the delivery status of a specific message by ID
router.get('/:id', messageController.getMessageStatus);

// List all messages for the authenticated user
router.get('/', messageController.getUserMessages);

module.exports = router;

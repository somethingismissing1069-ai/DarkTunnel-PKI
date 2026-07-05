/**
 * DarkTunnel PKI Web - Relay Routes
 * 
 * Defines routes for the onion routing relay simulation.
 * This endpoint processes encrypted packets through the 3-node relay.
 * 
 * POST /api/relay/process - Process an onion packet (Node A → B → C)
 */

const router = require('express').Router();
const relayController = require('../controllers/relayController');

// Process an onion packet through the relay network
// Note: No auth middleware - relay processes packets from any source
router.post('/process', relayController.processPacket);

module.exports = router;

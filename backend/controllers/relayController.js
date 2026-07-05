/**
 * DarkTunnel PKI Web - Relay Controller
 * 
 * Handles onion packet processing through the relay simulation.
 * This endpoint can be called directly for testing the relay layer
 * independently of the message service flow.
 * 
 * POST /api/relay/process - Process an onion packet (Node A → B → C)
 */

const relayEngine = require('../services/relayEngine');

/**
 * POST /api/relay/process
 * Process an onion packet through the 3-node relay network.
 * Each node decrypts one encryption layer in sequence.
 * 
 * Body: { onionPacket: { nonce, timestamp, packet, layers, version } }
 * Response 200: { success: true, data: { plaintext, status } }
 * Response 400: { success: false, error: string }
 */
exports.processPacket = (req, res, next) => {
  try {
    const { onionPacket } = req.body;

    if (!onionPacket) {
      return res.status(400).json({
        success: false,
        error: 'onionPacket is required in request body'
      });
    }

    const result = relayEngine.processPacket(onionPacket);

    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    // Relay errors (replay attacks, timestamp issues) return 400
    if (err.message.includes('Replay') || err.message.includes('timestamp') ||
        err.message.includes('nonce')) {
      return res.status(400).json({
        success: false,
        error: err.message
      });
    }
    next(err);
  }
};

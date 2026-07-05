/**
 * DarkTunnel PKI Web - Express Application Entry Point
 * 
 * Sets up the Express server with:
 * - JSON body parsing
 * - CORS for frontend communication
 * - Rate limiting for DDoS protection
 * - Route mounting for all API endpoints
 * - Global error handler for consistent error responses
 * - Database initialization on startup
 * - PKI service initialization (CA + relay nodes)
 * 
 * API Routes:
 *   POST /api/register           - User registration
 *   POST /api/login              - User login
 *   POST /api/pki/generate-cert  - Certificate generation
 *   GET  /api/pki/verify/:id     - Certificate verification
 *   POST /api/pki/revoke         - Certificate revocation
 *   POST /api/message/send       - Send encrypted message
 *   GET  /api/message/:id        - Get message status
 *   GET  /api/messages           - List user messages
 *   POST /api/relay/process      - Process onion packet
 *   GET  /api/admin/logs         - View audit logs
 */

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');

// Create Express application instance
const app = express();

// ─── Middleware ──────────────────────────────────────────────────────────────

// Parse JSON request bodies (required for all API endpoints)
app.use(express.json());

// Enable CORS for frontend communication (React dev server on different port)
app.use(cors());

// Apply general rate limiting to all API endpoints
const { generalLimiter } = require('./middleware/rateLimiter');
app.use('/api', generalLimiter);

// ─── Route Registration ─────────────────────────────────────────────────────

// Import route modules
const authRoutes = require('./routes/authRoutes');
const pkiRoutes = require('./routes/pkiRoutes');
const messageRoutes = require('./routes/messageRoutes');
const relayRoutes = require('./routes/relayRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Mount routes at their respective API paths
app.use('/api', authRoutes);             // /api/register, /api/login
app.use('/api/pki', pkiRoutes);          // /api/pki/generate-cert, /api/pki/verify/:id, /api/pki/revoke
app.use('/api/message', messageRoutes);  // /api/message/send, /api/message/:id
app.use('/api/messages', messageRoutes); // /api/messages (list user messages)
app.use('/api/relay', relayRoutes);      // /api/relay/process
app.use('/api/admin', adminRoutes);      // /api/admin/logs

// ─── Global Error Handler ───────────────────────────────────────────────────

/**
 * Global error handling middleware.
 * Catches any errors thrown in route handlers and returns a consistent
 * JSON error response format: { success: false, error: message }
 * 
 * In production, internal errors return a generic message to avoid
 * leaking implementation details.
 */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);

  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 ? 'Internal server error' : err.message;

  res.status(statusCode).json({
    success: false,
    error: message
  });
});

// ─── Server Startup ─────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;

/**
 * Initialize the application:
 * 1. Initialize the SQLite database (creates tables if needed)
 * 2. Initialize PKI service (CA key pair, relay nodes)
 * 3. Start the Express server
 */
function start() {
  try {
    // Initialize database (creates tables and indexes)
    require('./models/db');
    console.log('[SERVER] Database initialized');

    // Initialize PKI service (CA setup, relay node creation)
    const pkiService = require('./services/pkiService');
    pkiService.initialize();
    console.log('[SERVER] PKI service initialized');

    // Start listening for incoming requests
    app.listen(PORT, () => {
      console.log(`[SERVER] DarkTunnel PKI Web backend running on port ${PORT}`);
      console.log(`[SERVER] API available at http://localhost:${PORT}/api`);
    });
  } catch (error) {
    console.error('[FATAL] Failed to start server:', error.message);
    process.exit(1);
  }
}

start();

// Export app for testing
module.exports = app;

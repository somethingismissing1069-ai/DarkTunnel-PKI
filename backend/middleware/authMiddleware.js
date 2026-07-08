/**
 * DarkTunnel PKI Web - Authentication Middleware
 * 
 * Verifies JWT tokens from the Authorization header on protected routes.
 * Attaches decoded user payload (userId, username, role) to req.user.
 * Returns 401 for missing, expired, or invalid tokens.
 */

const jwt = require('jsonwebtoken');

/**
 * Express middleware that validates Bearer JWT tokens.
 * 
 * Expected header format: Authorization: Bearer <token>
 * 
 * On success: attaches decoded payload to req.user and calls next()
 * On failure: returns 401 JSON error response
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  // Check for Authorization header with Bearer prefix
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'No token provided'
    });
  }

  try {
    // Extract token from "Bearer <token>" format
    const token = authHeader.split(' ')[1];

    // Verify token signature and expiration
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user info to request for downstream handlers
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }
}

module.exports = authMiddleware;

/**
 * DarkTunnel PKI Web - Input Validation Middleware
 * 
 * Validates request bodies before they reach controllers.
 * Returns 400 with descriptive error messages on validation failure.
 * 
 * Validators:
 * - validateRegistration: username (3-30 chars) + password (8+ chars)
 * - validateLogin: username + password required
 * - validateSendMessage: content required (max 10000 chars)
 */

const constants = require('../config/constants');

/**
 * Validate registration request body.
 * Requires username (3-30 characters) and password (8+ characters).
 */
function validateRegistration(req, res, next) {
  const { username, password } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Username is required'
    });
  }

  if (username.length < constants.USERNAME_MIN_LENGTH ||
      username.length > constants.USERNAME_MAX_LENGTH) {
    return res.status(400).json({
      success: false,
      error: `Username must be ${constants.USERNAME_MIN_LENGTH}-${constants.USERNAME_MAX_LENGTH} characters`
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Password is required'
    });
  }

  if (password.length < constants.PASSWORD_MIN_LENGTH) {
    return res.status(400).json({
      success: false,
      error: `Password must be at least ${constants.PASSWORD_MIN_LENGTH} characters`
    });
  }

  next();
}

/**
 * Validate login request body.
 * Requires both username and password fields.
 */
function validateLogin(req, res, next) {
  const { username, password } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Username is required'
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Password is required'
    });
  }

  next();
}

/**
 * Validate send message request body.
 * Requires content field (max 10000 characters).
 */
function validateSendMessage(req, res, next) {
  const { content } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Message content is required'
    });
  }

  if (content.length > 10000) {
    return res.status(400).json({
      success: false,
      error: 'Message content must not exceed 10000 characters'
    });
  }

  next();
}

module.exports = { validateRegistration, validateLogin, validateSendMessage };

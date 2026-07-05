/**
 * DarkTunnel PKI Web - Authentication Controller
 * 
 * Handles HTTP requests for user registration and login.
 * Delegates business logic to authService.
 * 
 * POST /api/register - Create user account with RSA keys and certificate
 * POST /api/login    - Authenticate and return JWT token
 */

const authService = require('../services/authService');

/**
 * POST /api/register
 * Register a new user with username and password.
 * Generates RSA key pair and PKI certificate on successful registration.
 * 
 * Request body: { username: string, password: string }
 * Response 201: { success: true, data: { userId, username } }
 * Response 400/409: { success: false, error: string }
 */
exports.register = (req, res, next) => {
  try {
    const { username, password } = req.body;
    const result = authService.register(username, password);

    res.status(201).json({
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
 * POST /api/login
 * Authenticate a user and return a JWT session token.
 * 
 * Request body: { username: string, password: string }
 * Response 200: { success: true, data: { token } }
 * Response 401: { success: false, error: string }
 */
exports.login = (req, res, next) => {
  try {
    const { username, password } = req.body;
    const result = authService.login(username, password);

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

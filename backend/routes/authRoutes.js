/**
 * DarkTunnel PKI Web - Authentication Routes
 * 
 * Defines routes for user registration and login.
 * These endpoints are public (no JWT required).
 * Protected by rate limiting and input validation.
 * 
 * POST /api/register - Create a new user account
 * POST /api/login    - Authenticate and receive JWT
 */

const router = require('express').Router();
const authController = require('../controllers/authController');
const { loginLimiter } = require('../middleware/rateLimiter');
const { validateRegistration, validateLogin } = require('../middleware/validator');

// User registration - validates input, creates account with RSA keys and certificate
router.post('/register', validateRegistration, authController.register);

// User login - rate limited on failed attempts, returns JWT session token
router.post('/login', loginLimiter, validateLogin, authController.login);

module.exports = router;

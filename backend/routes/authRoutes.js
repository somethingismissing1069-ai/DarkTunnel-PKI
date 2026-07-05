/**
 * DarkTunnel PKI Web - Authentication Routes
 * 
 * Defines routes for user registration and login.
 * These endpoints are public (no JWT required).
 * 
 * POST /api/register - Create a new user account
 * POST /api/login    - Authenticate and receive JWT
 */

const router = require('express').Router();
const authController = require('../controllers/authController');

// User registration - creates account with RSA keys and certificate
router.post('/register', authController.register);

// User login - returns JWT session token
router.post('/login', authController.login);

module.exports = router;
